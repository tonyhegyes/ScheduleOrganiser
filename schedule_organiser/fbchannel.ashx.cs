﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace schedule_organiser
{
    public class FacebookChannelHandler : IHttpHandler
    {
        public void ProcessRequest(HttpContext context)
        {
            HttpResponse response = context.Response;
            response.ClearHeaders();

            const int cacheExpires = 60 * 60 * 24 * 365;
            response.AppendHeader("Pragma", "public");
            response.AppendHeader("Cache-Control", "max-age=" + cacheExpires);
            response.AppendHeader("Expires", DateTime.Now.ToUniversalTime().AddSeconds(cacheExpires).ToString("r"));
            context.Response.ContentType = "text/html";
            context.Response.Write("<script src=\"//connect.facebook.net/en_US/all.js\"></script>");
        }

        public bool IsReusable { get { return false; } }
    }
}