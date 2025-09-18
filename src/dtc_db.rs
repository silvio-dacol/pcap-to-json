use serde::Serialize;
use std::{
    fs::File,
    io::Write,
};

use calamine::{open_workbook_auto, Data, Reader};

#[derive(Serialize)]
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
// Output: JSONL with { dtc, description } where description is everything
// after the first '|' (if multiple parts exist, they are preserved joined by '|').
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

    let mut out = File::create(out_path)?;

    for (row_idx, row) in range.rows().enumerate() {
        // Skip header row
        if row_idx == 0 { continue; }

        // Column C -> index 2, expected format: DTC|Description...
        let raw = match row.get(2).and_then(cell_to_string) {
            Some(v) if !v.trim().is_empty() => v,
            _ => continue, // no data in this row
        };

        let mut parts = raw.split('|').map(|s| s.trim()).filter(|s| !s.is_empty());
        let dtc = match parts.next() {
            Some(code) => code.to_string(),
            None => continue,
        };

        // Everything after the first '|' is the description (may include additional '|')
        let rest: Vec<String> = parts.map(|s| s.to_string()).collect();
        if rest.is_empty() { continue; }
        let description_joined = rest.join("|");

        let rec = DtcDbRecord { dtc, description: description_joined };
        writeln!(out, "{}", serde_json::to_string(&rec)?)?;
    }

    Ok(())
}
