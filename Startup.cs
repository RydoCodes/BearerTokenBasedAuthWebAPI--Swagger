using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using TokenBasedAuthWebAPI.Data;
using TokenBasedAuthWebAPI.Data.Models;
using Microsoft.OpenApi.Models;

namespace TokenBasedAuthWebAPI
{
	public class Startup
	{
		public string ConnectionString { get; set; }
		public Startup(IConfiguration configuration)
		{
			Configuration = configuration;
			ConnectionString = Configuration.GetConnectionString("DefaultConnection");
		}

		public IConfiguration Configuration { get; }

		// This method gets called by the runtime. Use this method to add services to the container.
		public void ConfigureServices(IServiceCollection services)
		{
			// Configure DBContext with SQL
			services.AddDbContext<AppDbContext>(options => options.UseSqlServer(ConnectionString));

			// Add Identity
			services.AddIdentity<ApplicationUser, IdentityRole>()
				.AddEntityFrameworkStores<AppDbContext>()
				.AddDefaultTokenProviders();

			// Add Authentication

			services.AddAuthentication(rydooptions =>
			{
				rydooptions.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
				rydooptions.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
				rydooptions.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
			})
				// Add JWT Bearer
				.AddJwtBearer(rydooptions=> {
					rydooptions.SaveToken = true;
					rydooptions.RequireHttpsMetadata = false;
					rydooptions.TokenValidationParameters = new TokenValidationParameters()
					{
						ValidateIssuerSigningKey = true,
						IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Configuration["JWT:Secret"])),

						ValidateIssuer = true,
						ValidIssuer= Configuration["JWT:Issuer"],

						ValidateAudience = true,
						ValidAudience = Configuration["JWT:Audience"]

					};
				});

			services.AddControllers();

			services.AddSwaggerGen(rydoc=> {
				rydoc.SwaggerDoc("v1", new OpenApiInfo { Title = "Rydo Tokens API", Version = "v1", Description="This is to understand Token Based Auth" });
			});
		}

		// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
		public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
		{
			if (env.IsDevelopment())
			{
				app.UseDeveloperExceptionPage();
				app.UseSwagger();
				app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json","Rydo Token API"));
			}

			app.UseHttpsRedirection();

			app.UseRouting();

			app.UseAuthentication();

			app.UseAuthorization();

			app.UseEndpoints(endpoints =>
			{
				endpoints.MapControllers();
			});
		}
	}
}
