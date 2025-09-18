use serde::Serialize;
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
};
use std::path::Path;

use crate::dtc_db;

#[derive(Serialize)]
struct DtcRecord {
    dtc: String,
    display_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    ecu: String,
    masked: bool,
    status: u32,
}

// Convert a 6-hex-char raw DTC (e.g., "1ABCD2") to display code (e.g., "C1ABCD").
// Mirrors the provided Python implementation and the original Excel formula.
fn dtc_hex_to_display<S: AsRef<str>>(a7: S) -> Result<String, String> {
    let s_in = a7.as_ref();
    if s_in.is_empty() {
        return Err("Empty input".to_string());
    }

    // Normalize: trim, upper-case, remove optional leading 0X
    let mut s = s_in.trim().to_uppercase();
    if s.starts_with("0X") {
        s = s[2..].to_string();
    }
    if s.is_empty() {
        return Err("Input must contain at least 1 hex character".to_string());
    }

    // First nibble as int
    let first_char = s.chars().next().ok_or_else(|| "Input must contain at least 1 hex character".to_string())?;
    let nibble = first_char
        .to_digit(16)
        .ok_or_else(|| format!("First character '{}' is not hex", first_char))? as u8;

    // Top 2 bits -> system letter
    let sys_bits = (nibble & 0b1100) >> 2; // bits 3..2
    let system = match sys_bits {
        0 => 'P',
        1 => 'C',
        2 => 'B',
        3 => 'U',
        _ => 'X',
    };

    // Bottom 2 bits -> second hex char (0..3)
    let sub_bits = nibble & 0b0011;
    let second_char = format!("{:X}", sub_bits);

    // Next five characters from the original (1-indexed MID(A7,2,5) => s[1:6])
    // If input shorter than 6 chars, this will yield fewer chars, matching Python slicing behavior.
    let remainder: String = s.chars().skip(1).take(5).collect();

    Ok(format!("{}{}{}", system, second_char, remainder))
}

pub fn extract_dtcs_from_log(
    in_path: &str,
    out_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let infile = File::open(in_path)?;
    let reader = BufReader::new(infile);
    if let Some(parent) = std::path::Path::new(out_path).parent() { let _ = std::fs::create_dir_all(parent); }
    let mut outfile = File::create(out_path)?;

    // Try to load DTC descriptions from default JSONL, warn if the file is missing.
    let dtc_db_default = Path::new("files/input/dtcs_db.jsonl");
    let dtc_map = if dtc_db_default.exists() {
        match dtc_db::load_dtc_map_from_jsonl(dtc_db_default) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Warning: failed to load dtcs_db.jsonl: {}. Descriptions will be omitted.", e);
                std::collections::HashMap::new()
            }
        }
    } else {
        eprintln!("Info: files/input/dtcs_db.jsonl not found. Continuing without descriptions.");
        std::collections::HashMap::new()
    };

    let mut in_section = false;
    let mut saw_header = false;

    for line_res in reader.lines() {
        let mut line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };

        if !in_section {
            if line.contains("DTC Summary.") && line.contains("[IA]") {
                in_section = true;
                saw_header = false;
            }
            continue;
        }

        if line.contains("End of DTC Summary.") && line.contains("[IA]") {
            break;
        }

        if !saw_header {
            if line.contains("DTC")
                && line.contains("ECU")
                && line.contains("Masked")
                && line.contains("Status")
            {
                saw_header = true;
            }
            continue;
        }

        let after_tag = if let Some(pos) = line.rfind("] [IA] ") {
            line.split_off(pos + "] [IA] ".len())
        } else if let Some(pos) = line.rfind("[IA] ") {
            line.split_off(pos + "[IA] ".len())
        } else {
            line
        };

        let trimmed = after_tag.trim_end_matches('.').trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let dtc = match parts.next() {
            Some(v) => v.trim_end_matches('.'),
            None => continue,
        };
        let ecu = match parts.next() {
            Some(v) => v.trim_end_matches('.'),
            None => continue,
        };
        let masked_raw = match parts.next() {
            Some(v) => v.trim_end_matches('.'),
            None => continue,
        };
        let status_raw = match parts.next() {
            Some(v) => v.trim_end_matches('.'),
            None => continue,
        };

        if dtc.eq_ignore_ascii_case("DTC") || ecu.eq_ignore_ascii_case("ECU") {
            continue;
        }

        let masked = match masked_raw {
            "true" | "True" | "TRUE" => true,
            "false" | "False" | "FALSE" => false,
            _ => continue,
        };

        let status_clean = status_raw.trim_matches(|c: char| !c.is_ascii_digit());
        if status_clean.is_empty() {
            continue;
        }
        let status: u32 = match status_clean.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let display_code = dtc_hex_to_display(dtc).unwrap_or_else(|_| dtc.to_string());
        let description = dtc_map.get(&display_code).cloned();
        let rec = DtcRecord {
            dtc: dtc.to_string(),
            display_code,
            description,
            ecu: ecu.to_string(),
            masked,
            status,
        };
        writeln!(outfile, "{}", serde_json::to_string(&rec)?)?;
    }

    Ok(())
}
