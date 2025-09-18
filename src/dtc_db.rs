use serde::{Serialize, Deserialize};
use std::{
    fs::File,
    io::{Write, BufRead, BufReader},
};
use std::collections::HashMap;
use std::path::Path;

use calamine::{open_workbook_auto, Data, Reader};

#[derive(Serialize, Deserialize)]
struct DtcDbRecord {
    dtc: String,
    description: String,
}

fn cell_to_string(cell: &Data) -> Option<String> {
    match cell {
        Data::Empty => None,
        Data::String(s) => {
            let t = s.trim();
            if t.is_empty() { None } else { Some(t.to_string()) }
        }
        Data::Float(f) => Some({
            // Avoid trailing ".0" for integer-like floats
            if f.fract() == 0.0 { format!("{}", *f as i64) } else { f.to_string() }
        }),
        Data::Int(i) => Some(i.to_string()),
        Data::Bool(b) => Some(b.to_string()),
        other => {
            let s = other.to_string();
            let t = s.trim();
            if t.is_empty() { None } else { Some(t.to_string()) }
        }
    }
}

// Extract DTC descriptions from an .xlsx sheet.
// Assumptions (per user clarification):
// - Row 1 is a header and should be skipped.
// - Columns A and B are not useful.
// - Column C contains a single string with the format:
//   "<DTC>|<description>[|<alt description> ...]".
// Output: JSONL with { dtc, description } where description is only the text
// immediately after the first '|' (subsequent '|' parts are ignored).
pub fn extract_dtcs_from_xlsx(
    in_path: &str,
    out_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut workbook = open_workbook_auto(in_path)?;

    // Use the first available worksheet
    let sheet_name = workbook
        .sheet_names()
        .get(0)
        .cloned()
        .ok_or("XLSX has no sheets")?;

    let range = workbook
        .worksheet_range(&sheet_name)?;

    if let Some(parent) = std::path::Path::new(out_path).parent() { let _ = std::fs::create_dir_all(parent); }
    let mut out = File::create(out_path)?;

    for (row_idx, row) in range.rows().enumerate() {
        // Skip header row
        if row_idx == 0 { continue; }

        // Column C -> index 2, expected format: DTC|Description...
        let raw = match row.get(2).and_then(cell_to_string) {
            Some(v) if !v.trim().is_empty() => v,
            _ => continue, // no data in this row
        };

        // We expect format: <DTC>|<ignored>|<description ... possibly more '|'>
        let mut parts = raw.splitn(3, '|');
        let dtc = match parts.next().map(|s| s.trim()) {
            Some(code) if !code.is_empty() => code.to_string(),
            _ => continue,
        };
        // Skip the second segment (could be empty/ignored)
        let _ignored = parts.next();
        // Everything from after the second '|' to the end is the description
        let description = match parts.next() {
            Some(rest) if !rest.trim().is_empty() => rest.trim().to_string(),
            _ => continue,
        };

        let rec = DtcDbRecord { dtc, description };
        writeln!(out, "{}", serde_json::to_string(&rec)?)?;
    }

    Ok(())
}

// Load a map of display_code -> description from a JSONL file.
// If the file is missing, returns an empty map (caller can decide whether to warn).
pub fn load_dtc_map_from_jsonl<P: AsRef<Path>>(path: P) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let p = path.as_ref();
    let mut map = HashMap::new();
    let file = File::open(p)?; // let caller decide how to handle NotFound
    let reader = BufReader::new(file);
    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };
        if line.trim().is_empty() { continue; }
        if let Ok(rec) = serde_json::from_str::<DtcDbRecord>(&line) {
            map.insert(rec.dtc, rec.description);
        }
    }
    Ok(map)
}
