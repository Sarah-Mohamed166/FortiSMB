// lib/data/models/prediction_request.dart
// SOURCE: main.py → class QueryRequest(BaseModel)
// Every field matches the FastAPI Pydantic model exactly

class PredictionRequest {
  /// Required. Natural-language description of the event.
  final String aiQuery;

  /// Required. Literal["logon", "file", "device"]  (from main.py)
  final String action;

  /// Required. One of FortiSMBRoles.all  (from main.py)
  final String fortismbRole;

  /// Optional. File operation: read, write, copy, delete. Default "".
  final String fileOp;

  /// Optional. True if USB/removable media involved. Default false.
  final bool isUsb;

  /// Required. Hour 0–23  (from main.py Field ge=0, le=23)
  final double hour;

  /// Required. True if outside 08:00–18:00 working hours.
  final bool offHours;

  /// Optional. Date string e.g. "2026-04-26"
  final String? date;

  const PredictionRequest({
    required this.aiQuery,
    required this.action,
    required this.fortismbRole,
    this.fileOp = '',
    this.isUsb = false,
    required this.hour,
    this.offHours = false,
    this.date,
  });

  /// Serialises to the exact JSON the /predict endpoint expects
  Map<String, dynamic> toJson() => {
    'ai_query':       aiQuery,
    'action':         action,
    'fortismb_role':  fortismbRole,
    'file_op':        fileOp,
    'is_usb':         isUsb,
    'hour':           hour,
    'off_hours':      offHours,
    if (date != null) 'date': date,
  };
}
