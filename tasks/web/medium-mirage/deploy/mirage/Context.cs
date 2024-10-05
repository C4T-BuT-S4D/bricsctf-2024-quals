using System.Net;
using System.Text;

namespace Mirage {
    public class Context {
        private readonly HttpListenerRequest request;
        private readonly HttpListenerResponse response;

        public Context(HttpListenerContext context) {
            request = context.Request;
            response = context.Response;
        }

        public HttpListenerRequest Request => request;
        public HttpListenerResponse Response => response;

        public async Task Result(string content) {
            var bytes = Encoding.UTF8.GetBytes(content);

            await response.OutputStream.WriteAsync(bytes);
            await response.OutputStream.DisposeAsync();
        }

        public string? GetCookie(string name) {
            return Request.Cookies[name]?.Value;
        }

        public void SetCookie(string name, string value) {
            Response.AddHeader("Set-Cookie", $"{name}={value}; HttpOnly; SameSite=Lax");
        }

        public string? GetHeader(string name) {
            return Request.Headers[name];
        }

        public void SetHeader(string name, string value) {
            Response.AddHeader(name, value);
        }
    }
}
