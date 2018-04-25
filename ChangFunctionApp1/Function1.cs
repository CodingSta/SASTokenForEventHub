using System;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Host;
namespace SASTokenApp
{
    public static class SASTokenForEventHubs
    {
        [FunctionName("SASTokenForEventHubs")]
        public static async Task<HttpResponseMessage> Run([HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)]HttpRequestMessage req, TraceWriter log)
        {
            log.Info("C# HTTP trigger function processed a request.");
            // 로컬 또는 Azure Function App 의 Application Settings 에서 가져오게될 환경변수 값.
            string resourceUri = System.Environment.GetEnvironmentVariable("eventHubResourceUri", EnvironmentVariableTarget.Process);
            string keyName = System.Environment.GetEnvironmentVariable("eventHubKeyName", EnvironmentVariableTarget.Process);
            string key = System.Environment.GetEnvironmentVariable("eventHubKey", EnvironmentVariableTarget.Process);

            // Token 의 유효기간을 설정하기 위한 코드.
            TimeSpan sinceEpoch = DateTime.UtcNow - new DateTime(1970, 1, 1);
            var week = 60 * 60 * 24 * 365;
            var expiry = Convert.ToString((int)sinceEpoch.TotalSeconds + week);

            // 인코딩을 거쳐서 SAS Token 생성.
            string stringToSign = HttpUtility.UrlEncode(resourceUri) + "\n" + expiry;
            HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
            var signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));
            var sasToken = String.Format(CultureInfo.InvariantCulture, "SharedAccessSignature sr={0}&sig={1}&se={2}&skn={3}", HttpUtility.UrlEncode(resourceUri), HttpUtility.UrlEncode(signature), expiry, keyName);
            return req.CreateResponse(HttpStatusCode.OK, sasToken);
        }
    }
}