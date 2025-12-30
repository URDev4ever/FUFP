<%@ WebHandler Language="C#" %>
public void ProcessRequest(HttpContext ctx) {
  ctx.Response.Write("ASHX_TEST");
}