using System;

using Xamarin.Forms;

namespace webview
{
	public class App : Application
	{
		public Page LastPage;

		public App ()
		{
			// The root page of your application
			MainPage = new NavigationPage(new ButtonPage());
		}

		protected override void OnStart ()
		{
			// Handle when your app starts
		}

		protected override void OnSleep ()
		{
		}

		protected override void OnResume ()
		{
		}
	}
}

