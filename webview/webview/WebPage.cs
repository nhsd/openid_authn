using System;

using Xamarin.Forms;
using System.Collections.Generic;

namespace webview
{
	public class WebPage : ContentPage
	{
		private WebView webView;

		public WebPage (string uri)
		{
			webView = new WebView {
				HorizontalOptions = LayoutOptions.FillAndExpand,
				VerticalOptions = LayoutOptions.FillAndExpand,
				Source = uri
			};

			Content = new StackLayout {
				Children = {
					webView
				}
			};

			webView.Navigating += webOnNavigating;
		}

		private void webOnNavigating (object sender, WebNavigatingEventArgs e) {

			if (!e.Url.StartsWith ("http://localhost:5000")) {
				return;
			}

			System.Console.Out.WriteLine ("Cancelled navigation to:" + e.Url);
			e.Cancel = true;

			var argMap = new Dictionary<String, String> ();

			var args = e.Url.Split ('?')[1];
			foreach (var arg in args.Split('&')) {
				var values = arg.Split ('=');
				argMap [values [0]] = values [1];
			}
				
			var redirect = argMap ["redirect_uri"];
			redirect = redirect.Replace ("%3A", ":").Replace ("%2F", "/");

			webView.Source = redirect + "?code=James";
		}
	}
}

