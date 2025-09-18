use serde::Serialize;
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
};

#[derive(Serialize)]
struct DtcRecord {
    dtc: String,
    ecu: String,
    masked: bool,
    status: u32,
}

pub fn extract_dtcs_from_log(
    in_path: &str,
    out_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let infile = File::open(in_path)?;
    let reader = BufReader::new(infile);
    let mut outfile = File::create(out_path)?;

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

        let rec = DtcRecord {
            dtc: dtc.to_string(),
            ecu: ecu.to_string(),
            masked,
            status,
        };
        writeln!(outfile, "{}", serde_json::to_string(&rec)?)?;
    }

    Ok(())
}

