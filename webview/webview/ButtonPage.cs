using System;

using Xamarin.Forms;
using System.Collections.Generic;

namespace webview
{
	public class ButtonPage : ContentPage
	{
		private List<Tuple<String, String>> applications = new List<Tuple<String, String>> { 
			Tuple.Create( "emis", "http://192.168.1.6:5001/")
		};

	    class AppButton : Button {
		
		    public String Url;

			public AppButton(string text, string url) : base() {
				this.Text = text;
				this.Url = url;
			}
		}

		public ButtonPage ()
		{
			var content = new StackLayout ();

			foreach (var app in applications) {
				var button = new AppButton (app.Item1, app.Item2);
				button.Clicked += OnAppButtonclick;
				content.Children.Add (button);
			}

			Content = content;
		}

		private void OnAppButtonclick(object sender, EventArgs e) {

			var button = sender as AppButton;

			Navigation.PushAsync(new WebPage(button.Url));
		}
	}
}

