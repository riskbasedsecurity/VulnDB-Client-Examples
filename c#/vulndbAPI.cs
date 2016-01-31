using DevDefined.OAuth.Consumer;
using DevDefined.OAuth.Framework;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Windows.Forms;

namespace CMS_Auditor
{
    class vulndbAPI
    {
        /// <summary>
        /// Used to Check if the API key is valid or not.
        /// </summary>
        /// <param name="consumerkey"></param>
        /// <param name="consumersecret"></param>
        /// <returns></returns>
        public static string CMS_Auditor(String consumerkey, String consumersecret)
        {
            try
            {
                var requestEndPoint = new Uri("https://vulndb.cyberriskanalytics.com/oauth/request_token");
                var authorizeEndPoint = new Uri("https://vulndb.cyberriskanalytics.com/oauth/authorize");
                var accessEndPoint = new Uri("https://vulndb.cyberriskanalytics.com/oauth/access_token");
                var ctx = new OAuthConsumerContext
                {
                    ConsumerKey = consumerkey,
                    ConsumerSecret = consumersecret,
                    SignatureMethod = SignatureMethod.HmacSha1
                };
                var genericSession = new OAuthSession(ctx, requestEndPoint, authorizeEndPoint, accessEndPoint);
                var targetServiceUri = new Uri("https://vulndb.cyberriskanalytics.com/api/v1/vulnerabilities/search_query?utf8=✓&query=teamviewer");
                var respText = genericSession.Request().Get().ForUri(targetServiceUri).ToString();

                return respText;

            }
            catch (WebException ex)
            {
                using (var stream = ex.Response.GetResponseStream())
                using (var reader = new StreamReader(stream))
                {
                    Console.WriteLine(reader.ReadToEnd());
                    return "Please Check your API Key and Secret";
                }
            }
        }
        /// <summary>
        /// Checks a single entry agasint vulnDB Search API.
        /// </summary>
        /// <param name="consumerkey"></param>
        /// <param name="consumersecret"></param>
        /// <param name="Application"></param>
        /// <returns></returns>
        public static string vulndb_appCheck(String consumerkey, String consumersecret, String Application)
        {
            try
            {
                var requestEndPoint = new Uri("https://vulndb.cyberriskanalytics.com/oauth/request_token");
                var authorizeEndPoint = new Uri("https://vulndb.cyberriskanalytics.com/oauth/authorize");
                var accessEndPoint = new Uri("https://vulndb.cyberriskanalytics.com/oauth/access_token");
                var ctx = new OAuthConsumerContext
                {
                    ConsumerKey = consumerkey,
                    ConsumerSecret = consumersecret,
                    SignatureMethod = SignatureMethod.HmacSha1
                };
                var genericSession = new OAuthSession(ctx, requestEndPoint, authorizeEndPoint, accessEndPoint);
                var targetServiceUri = new Uri("https://vulndb.cyberriskanalytics.com/api/v1/vulnerabilities/search_query?query=\"" + Application.ToString() +"\"");
                var respText = genericSession.Request().Get().ForUri(targetServiceUri).ToString();
               
                return respText;

            }
            catch (WebException ex)
            {
                using (var stream = ex.Response.GetResponseStream())
                using (var reader = new StreamReader(stream))
                {
                    Console.WriteLine(reader.ReadToEnd());
                    return "Nothing Found for: " + Application.ToString();
                }
            }
        }
        /// <summary>
        /// Used to Check if the API key is valid or not.
        /// </summary>
        /// <param name="consumerkey"></param>
        /// <param name="consumersecret"></param>
        /// <returns></returns>
        public static Boolean vulndbCheckCredentials(String consumerkey, String consumersecret)
        {
            if (consumerkey == "" || consumersecret == "") { return false; }
            try
            {
                var requestEndPoint = new Uri("https://vulndb.cyberriskanalytics.com/oauth/request_token");
                var authorizeEndPoint = new Uri("https://vulndb.cyberriskanalytics.com/oauth/authorize");
                var accessEndPoint = new Uri("https://vulndb.cyberriskanalytics.com/oauth/access_token");
                var ctx = new OAuthConsumerContext
                {
                    ConsumerKey = consumerkey,
                    ConsumerSecret = consumersecret,
                    SignatureMethod = SignatureMethod.HmacSha1
                };
                var genericSession = new OAuthSession(ctx, requestEndPoint, authorizeEndPoint, accessEndPoint);
                var targetServiceUri = new Uri("https://vulndb.cyberriskanalytics.com/api/v1/vulnerabilities/");
                var respText = genericSession.Request().Get().ForUri(targetServiceUri).ToString();

                return true;

            }
            catch (WebException ex)
            {
                using (var stream = ex.Response.GetResponseStream())
                using (var reader = new StreamReader(stream))
                {
                    Console.WriteLine(reader.ReadToEnd());
                    return false;
                }
            }
        }
    }
}
