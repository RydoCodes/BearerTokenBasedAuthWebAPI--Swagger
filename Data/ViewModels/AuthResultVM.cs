﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TokenBasedAuthWebAPI.Data.ViewModels
{
	public class AuthResultVM
	{
		public string Token { get; set; }
		public DateTime ExpiresAt { get; set; }
	}
}