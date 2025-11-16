using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Application.DTOs.Common
{
    public class ApiResponse<T>
    {

        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public int Code { get; set; }
        public T? Data { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        public static ApiResponse<T> SuccessResult(T data, string message = "Operation completed successfully")
        {
            return new ApiResponse<T>
            {
                Success = true,
                Message = message,
                Code = 0, // 0 = Success
                Data = data
            };
        }

        public static ApiResponse<T> ErrorResult(string message, int code = 500)
        {
            return new ApiResponse<T>
            {
                Success = false,
                Message = message,
                Code = code,
                Data = default
            };
        }
    }

    // Common response codes
    public static class ResponseCodes
    {
        // Success codes
        public const int SUCCESS = 0;
        public const int CREATED = 1;
        public const int UPDATED = 2;

        // Error codes
        public const int VALIDATION_ERROR = 400;
        public const int UNAUTHORIZED = 401;
        public const int FORBIDDEN = 403;
        public const int NOT_FOUND = 404;
        public const int CONFLICT = 409;
        public const int SERVER_ERROR = 500;
        public const int SERVICE_UNAVAILABLE = 503;
    }
}