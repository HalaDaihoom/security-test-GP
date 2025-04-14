using System;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Api.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AspNetRoles",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", nullable: false, collation: "utf8mb4_unicode_ci"),
                    Name = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: true, collation: "utf8mb4_unicode_ci"),
                    NormalizedName = table.Column<string>(type: "varchar(191)", maxLength: 191, nullable: true, collation: "utf8mb4_unicode_ci"),
                    ConcurrencyStamp = table.Column<string>(type: "longtext", nullable: true, collation: "utf8mb4_unicode_ci")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetRoles", x => x.Id);
                })
                .Annotation("Relational:Collation", "utf8mb4_unicode_ci");

            migrationBuilder.CreateTable(
                name: "AspNetUsers",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", nullable: false, collation: "utf8mb4_unicode_ci"),
                    FirstName = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: false, collation: "utf8mb4_unicode_ci"),
                    LastName = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: false, collation: "utf8mb4_unicode_ci"),
                    Gender = table.Column<string>(type: "longtext", nullable: true, collation: "utf8mb4_unicode_ci"),
                    Image = table.Column<byte[]>(type: "longblob", nullable: true),
                    UserName = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: true, collation: "utf8mb4_unicode_ci"),
                    NormalizedUserName = table.Column<string>(type: "varchar(191)", maxLength: 191, nullable: true, collation: "utf8mb4_unicode_ci"),
                    Email = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: true, collation: "utf8mb4_unicode_ci"),
                    NormalizedEmail = table.Column<string>(type: "varchar(191)", maxLength: 191, nullable: true, collation: "utf8mb4_unicode_ci"),
                    EmailConfirmed = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    PasswordHash = table.Column<string>(type: "longtext", nullable: true, collation: "utf8mb4_unicode_ci"),
                    SecurityStamp = table.Column<string>(type: "longtext", nullable: true, collation: "utf8mb4_unicode_ci"),
                    ConcurrencyStamp = table.Column<string>(type: "longtext", nullable: true, collation: "utf8mb4_unicode_ci"),
                    PhoneNumber = table.Column<string>(type: "longtext", nullable: true, collation: "utf8mb4_unicode_ci"),
                    PhoneNumberConfirmed = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    TwoFactorEnabled = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    LockoutEnd = table.Column<DateTimeOffset>(type: "datetime(6)", nullable: true),
                    LockoutEnabled = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    AccessFailedCount = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUsers", x => x.Id);
                })
                .Annotation("Relational:Collation", "utf8mb4_unicode_ci");

            migrationBuilder.CreateTable(
                name: "Vulnerabilities",
                columns: table => new
                {
                    VulnerabilityId = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    VulnerabilityName = table.Column<string>(type: "longtext", nullable: false, collation: "utf8mb4_unicode_ci"),
                    Description = table.Column<string>(type: "longtext", nullable: true, collation: "utf8mb4_unicode_ci"),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Vulnerabilities", x => x.VulnerabilityId);
                })
                .Annotation("Relational:Collation", "utf8mb4_unicode_ci");

            migrationBuilder.CreateTable(
                name: "AspNetRoleClaims",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    RoleId = table.Column<string>(type: "varchar(255)", nullable: false, collation: "utf8mb4_unicode_ci"),
                    ClaimType = table.Column<string>(type: "longtext", nullable: true, collation: "utf8mb4_unicode_ci"),
                    ClaimValue = table.Column<string>(type: "longtext", nullable: true, collation: "utf8mb4_unicode_ci")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetRoleClaims", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AspNetRoleClaims_AspNetRoles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "AspNetRoles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("Relational:Collation", "utf8mb4_unicode_ci");

            migrationBuilder.CreateTable(
                name: "AspNetUserClaims",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    UserId = table.Column<string>(type: "varchar(255)", nullable: false, collation: "utf8mb4_unicode_ci"),
                    ClaimType = table.Column<string>(type: "longtext", nullable: true, collation: "utf8mb4_unicode_ci"),
                    ClaimValue = table.Column<string>(type: "longtext", nullable: true, collation: "utf8mb4_unicode_ci")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserClaims", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AspNetUserClaims_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("Relational:Collation", "utf8mb4_unicode_ci");

            migrationBuilder.CreateTable(
                name: "AspNetUserLogins",
                columns: table => new
                {
                    LoginProvider = table.Column<string>(type: "varchar(255)", nullable: false, collation: "utf8mb4_unicode_ci"),
                    ProviderKey = table.Column<string>(type: "varchar(255)", nullable: false, collation: "utf8mb4_unicode_ci"),
                    ProviderDisplayName = table.Column<string>(type: "longtext", nullable: true, collation: "utf8mb4_unicode_ci"),
                    UserId = table.Column<string>(type: "varchar(255)", nullable: false, collation: "utf8mb4_unicode_ci")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserLogins", x => new { x.LoginProvider, x.ProviderKey });
                    table.ForeignKey(
                        name: "FK_AspNetUserLogins_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("Relational:Collation", "utf8mb4_unicode_ci");

            migrationBuilder.CreateTable(
                name: "AspNetUserRoles",
                columns: table => new
                {
                    UserId = table.Column<string>(type: "varchar(255)", nullable: false, collation: "utf8mb4_unicode_ci"),
                    RoleId = table.Column<string>(type: "varchar(255)", nullable: false, collation: "utf8mb4_unicode_ci")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserRoles", x => new { x.UserId, x.RoleId });
                    table.ForeignKey(
                        name: "FK_AspNetUserRoles_AspNetRoles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "AspNetRoles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AspNetUserRoles_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("Relational:Collation", "utf8mb4_unicode_ci");

            migrationBuilder.CreateTable(
                name: "AspNetUserTokens",
                columns: table => new
                {
                    UserId = table.Column<string>(type: "varchar(255)", nullable: false, collation: "utf8mb4_unicode_ci"),
                    LoginProvider = table.Column<string>(type: "varchar(255)", nullable: false, collation: "utf8mb4_unicode_ci"),
                    Name = table.Column<string>(type: "varchar(255)", nullable: false, collation: "utf8mb4_unicode_ci"),
                    Value = table.Column<string>(type: "longtext", nullable: true, collation: "utf8mb4_unicode_ci")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserTokens", x => new { x.UserId, x.LoginProvider, x.Name });
                    table.ForeignKey(
                        name: "FK_AspNetUserTokens_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("Relational:Collation", "utf8mb4_unicode_ci");

            migrationBuilder.CreateTable(
                name: "Websites",
                columns: table => new
                {
                    WebsiteId = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    UserId = table.Column<string>(type: "varchar(255)", nullable: true, collation: "utf8mb4_unicode_ci"),
                    Url = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false, collation: "utf8mb4_unicode_ci"),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Websites", x => x.WebsiteId);
                    table.ForeignKey(
                        name: "FK_Websites_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id");
                })
                .Annotation("Relational:Collation", "utf8mb4_unicode_ci");

            migrationBuilder.CreateTable(
                name: "ScanRequests",
                columns: table => new
                {
                    RequestId = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    UserId = table.Column<string>(type: "varchar(255)", nullable: false, collation: "utf8mb4_unicode_ci"),
                    WebsiteId = table.Column<int>(type: "int", nullable: false),
                    ZAPScanId = table.Column<int>(type: "int", nullable: true),
                    Status = table.Column<string>(type: "longtext", nullable: false, collation: "utf8mb4_unicode_ci"),
                    StartedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    CompletedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    VulnerabilityId = table.Column<int>(type: "int", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScanRequests", x => x.RequestId);
                    table.ForeignKey(
                        name: "FK_ScanRequests_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_ScanRequests_Vulnerabilities_VulnerabilityId",
                        column: x => x.VulnerabilityId,
                        principalTable: "Vulnerabilities",
                        principalColumn: "VulnerabilityId");
                    table.ForeignKey(
                        name: "FK_ScanRequests_Websites_WebsiteId",
                        column: x => x.WebsiteId,
                        principalTable: "Websites",
                        principalColumn: "WebsiteId",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("Relational:Collation", "utf8mb4_unicode_ci");

            migrationBuilder.CreateTable(
                name: "ScanResults",
                columns: table => new
                {
                    ResultId = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    RequestId = table.Column<int>(type: "int", nullable: false),
                    ZAPScanId = table.Column<int>(type: "int", nullable: true),
                    VulnerabilityId = table.Column<int>(type: "int", nullable: true),
                    Severity = table.Column<string>(type: "longtext", nullable: true, collation: "utf8mb4_unicode_ci"),
                    Details = table.Column<string>(type: "longtext", nullable: true, collation: "utf8mb4_unicode_ci"),
                    Summary = table.Column<string>(type: "longtext", nullable: true, collation: "utf8mb4_unicode_ci")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScanResults", x => x.ResultId);
                    table.ForeignKey(
                        name: "FK_ScanResults_ScanRequests_RequestId",
                        column: x => x.RequestId,
                        principalTable: "ScanRequests",
                        principalColumn: "RequestId",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_ScanResults_Vulnerabilities_VulnerabilityId",
                        column: x => x.VulnerabilityId,
                        principalTable: "Vulnerabilities",
                        principalColumn: "VulnerabilityId");
                })
                .Annotation("Relational:Collation", "utf8mb4_unicode_ci");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetRoleClaims_RoleId",
                table: "AspNetRoleClaims",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "RoleNameIndex",
                table: "AspNetRoles",
                column: "NormalizedName",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserClaims_UserId",
                table: "AspNetUserClaims",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserLogins_UserId",
                table: "AspNetUserLogins",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserRoles_RoleId",
                table: "AspNetUserRoles",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "EmailIndex",
                table: "AspNetUsers",
                column: "NormalizedEmail");

            migrationBuilder.CreateIndex(
                name: "UserNameIndex",
                table: "AspNetUsers",
                column: "NormalizedUserName",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ScanRequests_UserId",
                table: "ScanRequests",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_ScanRequests_VulnerabilityId",
                table: "ScanRequests",
                column: "VulnerabilityId");

            migrationBuilder.CreateIndex(
                name: "IX_ScanRequests_WebsiteId",
                table: "ScanRequests",
                column: "WebsiteId");

            migrationBuilder.CreateIndex(
                name: "IX_ScanResults_RequestId",
                table: "ScanResults",
                column: "RequestId");

            migrationBuilder.CreateIndex(
                name: "IX_ScanResults_VulnerabilityId",
                table: "ScanResults",
                column: "VulnerabilityId");

            migrationBuilder.CreateIndex(
                name: "IX_Websites_UserId",
                table: "Websites",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AspNetRoleClaims");

            migrationBuilder.DropTable(
                name: "AspNetUserClaims");

            migrationBuilder.DropTable(
                name: "AspNetUserLogins");

            migrationBuilder.DropTable(
                name: "AspNetUserRoles");

            migrationBuilder.DropTable(
                name: "AspNetUserTokens");

            migrationBuilder.DropTable(
                name: "ScanResults");

            migrationBuilder.DropTable(
                name: "AspNetRoles");

            migrationBuilder.DropTable(
                name: "ScanRequests");

            migrationBuilder.DropTable(
                name: "Vulnerabilities");

            migrationBuilder.DropTable(
                name: "Websites");

            migrationBuilder.DropTable(
                name: "AspNetUsers");
        }
    }
}
