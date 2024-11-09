using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace finalAuth.Migrations
{
    /// <inheritdoc />
    public partial class RolesAdded : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "3c2a751a-0bba-446a-9c85-46f0cd86a9f5", "2", "User", "User" },
                    { "4788dc76-eef6-4da9-bec1-66dd66ae874d", "3", "Employee", "Employee" },
                    { "5213ff7c-fe93-4a4f-9829-c6ab21f94997", "1", "Admin", "Admin" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "3c2a751a-0bba-446a-9c85-46f0cd86a9f5");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "4788dc76-eef6-4da9-bec1-66dd66ae874d");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "5213ff7c-fe93-4a4f-9829-c6ab21f94997");
        }
    }
}
