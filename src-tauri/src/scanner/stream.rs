use crate::models::ScanReport;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ScanStreamEvent {
    Started,
    StdoutLine { line: String },
    StderrLine { line: String },
    ProgressHint { percent: f32, etc_seconds: Option<u32> },
    ParsedResult { report: ScanReport },
    Completed { exit_code: i32 },
    Cancelled,
    Failed { message: String },
}
