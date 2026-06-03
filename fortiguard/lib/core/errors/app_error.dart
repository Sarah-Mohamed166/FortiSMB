class AppError {
  final String message;
  final int? statusCode;
  const AppError({required this.message, this.statusCode});

  factory AppError.connection() =>
      const AppError(message: 'Cannot reach FortiSMB server. Is uvicorn running?');

  factory AppError.timeout() =>
      const AppError(message: 'Request timed out.');

  factory AppError.server(int code, String body) =>
      AppError(message: 'Server error $code: $body', statusCode: code);

  factory AppError.parse(String field) =>
      AppError(message: 'Failed to parse response field: $field');

  @override
  String toString() => message;
}