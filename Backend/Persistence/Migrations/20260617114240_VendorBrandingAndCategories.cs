using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace Persistence.Migrations
{
    /// <inheritdoc />
    public partial class VendorBrandingAndCategories : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                UPDATE "Products" SET "CategoryId" = 'cat-electronics' WHERE "CategoryId" = 'cat-phones';
                UPDATE "Products" SET "CategoryId" = 'cat-jewelry' WHERE "CategoryId" = 'cat-accessories';
                UPDATE "Products" SET "CategoryId" = 'cat-vehicle' WHERE "CategoryId" = 'cat-vehicles';
                """);

            migrationBuilder.DeleteData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-accessories");

            migrationBuilder.DeleteData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-phones");

            migrationBuilder.DeleteData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-vehicles");

            migrationBuilder.AddColumn<DateTime>(
                name: "BusinessCoverPhotoUpdatedAt",
                table: "Users",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "BusinessCoverPhotoUrl",
                table: "Users",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "BusinessLogoUpdatedAt",
                table: "Users",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.UpdateData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-electronics",
                columns: new[] { "Description", "DisplayOrder", "Name", "Slug" },
                values: new object[] { "Electronics & Gadgets", 2, "Electronics & Gadgets", "electronics-gadgets" });

            migrationBuilder.UpdateData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-fashion",
                columns: new[] { "Description", "DisplayOrder", "Name", "Slug" },
                values: new object[] { "Fashion & Clothing", 1, "Fashion & Clothing", "fashion-clothing" });

            migrationBuilder.UpdateData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-food",
                columns: new[] { "Description", "DisplayOrder", "Name", "Slug" },
                values: new object[] { "Food & Groceries", 7, "Food & Groceries", "food-groceries" });

            migrationBuilder.UpdateData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-health",
                columns: new[] { "Description", "DisplayOrder", "Name", "Slug" },
                values: new object[] { "Health & Wellness", 5, "Health & Wellness", "health-wellness" });

            migrationBuilder.UpdateData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-home",
                columns: new[] { "Description", "DisplayOrder", "Name", "Slug" },
                values: new object[] { "Home & Kitchen", 3, "Home & Kitchen", "home-kitchen" });

            migrationBuilder.UpdateData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-other",
                column: "Description",
                value: "Other");

            migrationBuilder.InsertData(
                table: "ProductCategories",
                columns: new[] { "Id", "CreatedAt", "Description", "DisplayOrder", "IsActive", "Name", "Slug" },
                values: new object[,]
                {
                    { "cat-art", new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "Art & Crafts", 15, true, "Art & Crafts", "art-crafts" },
                    { "cat-book", new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "Books & Stationery", 8, true, "Books & Stationery", "books-stationery" },
                    { "cat-build", new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "Building & Construction", 16, true, "Building & Construction", "building-construction" },
                    { "cat-care", new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "Beauty & Skincare", 4, true, "Beauty & Skincare", "beauty-skincare" },
                    { "cat-decor", new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "Furniture & Decor", 12, true, "Furniture & Decor", "furniture-decor" },
                    { "cat-farm", new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "Agriculture & Farm Supplies", 14, true, "Agriculture & Farm Supplies", "agriculture-farm" },
                    { "cat-game", new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "Toys & Games", 9, true, "Toys & Games", "toys-games" },
                    { "cat-jewelry", new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "Jewelry & Accessories", 13, true, "Jewelry & Accessories", "jewelry-accessories" },
                    { "cat-kid", new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "Baby & Kids", 10, true, "Baby & Kids", "baby-kids" },
                    { "cat-service", new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "Services", 17, true, "Services", "services" },
                    { "cat-sport", new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "Sports & Fitness", 6, true, "Sports & Fitness", "sports-fitness" },
                    { "cat-vehicle", new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "Automobiles & Parts", 11, true, "Automobiles & Parts", "automobiles-parts" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-art");

            migrationBuilder.DeleteData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-book");

            migrationBuilder.DeleteData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-build");

            migrationBuilder.DeleteData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-care");

            migrationBuilder.DeleteData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-decor");

            migrationBuilder.DeleteData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-farm");

            migrationBuilder.DeleteData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-game");

            migrationBuilder.DeleteData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-jewelry");

            migrationBuilder.DeleteData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-kid");

            migrationBuilder.DeleteData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-service");

            migrationBuilder.DeleteData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-sport");

            migrationBuilder.DeleteData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-vehicle");

            migrationBuilder.DropColumn(
                name: "BusinessCoverPhotoUpdatedAt",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "BusinessCoverPhotoUrl",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "BusinessLogoUpdatedAt",
                table: "Users");

            migrationBuilder.UpdateData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-electronics",
                columns: new[] { "Description", "Name", "Slug" },
                values: new object[] { "Electronics and gadgets", "Electronics", "electronics" });

            migrationBuilder.UpdateData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-fashion",
                columns: new[] { "Description", "DisplayOrder", "Name", "Slug" },
                values: new object[] { "Clothing and accessories", 3, "Fashion", "fashion" });

            migrationBuilder.UpdateData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-food",
                columns: new[] { "Description", "DisplayOrder", "Name", "Slug" },
                values: new object[] { "Food items and drinks", 4, "Food & Beverage", "food-beverage" });

            migrationBuilder.UpdateData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-health",
                columns: new[] { "Description", "DisplayOrder", "Name", "Slug" },
                values: new object[] { "Health and beauty products", 8, "Health & Beauty", "health-beauty" });

            migrationBuilder.UpdateData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-home",
                columns: new[] { "Description", "DisplayOrder", "Name", "Slug" },
                values: new object[] { "Home and garden items", 6, "Home & Garden", "home-garden" });

            migrationBuilder.UpdateData(
                table: "ProductCategories",
                keyColumn: "Id",
                keyValue: "cat-other",
                column: "Description",
                value: "Other items");

            migrationBuilder.InsertData(
                table: "ProductCategories",
                columns: new[] { "Id", "CreatedAt", "Description", "DisplayOrder", "IsActive", "Name", "Slug" },
                values: new object[,]
                {
                    { "cat-accessories", new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "Accessories and more", 5, true, "Accessories", "accessories" },
                    { "cat-phones", new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "Mobile phones and tablets", 1, true, "Phones & Tablets", "phones-tablets" },
                    { "cat-vehicles", new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "Cars, bikes and parts", 7, true, "Vehicles", "vehicles" }
                });
        }
    }
}
