-- =============================================================================
-- One-time script: align database with ProductCategories + Products.VendorId
-- Run in two batches so SQL Server compiles batch 2 after VendorId exists.
-- The app (Program.cs) splits on "GO" and runs each batch in order.
-- =============================================================================

-- BATCH 1: Create ProductCategories and ADD new columns to Products (no references to VendorId yet)
BEGIN TRANSACTION;

IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'ProductCategories')
BEGIN
    CREATE TABLE [ProductCategories] (
        [Id] nvarchar(450) NOT NULL,
        [Name] nvarchar(100) NOT NULL,
        [Slug] nvarchar(100) NOT NULL,
        [Description] nvarchar(500) NULL,
        [IsActive] bit NOT NULL,
        [DisplayOrder] int NOT NULL,
        [CreatedAt] datetime2 NOT NULL,
        CONSTRAINT [PK_ProductCategories] PRIMARY KEY ([Id])
    );
    CREATE UNIQUE INDEX [IX_ProductCategories_Slug] ON [ProductCategories] ([Slug]);

    DECLARE @SeedDate datetime2 = '2025-01-01 00:00:00';
    INSERT INTO [ProductCategories] ([Id], [Name], [Slug], [Description], [IsActive], [DisplayOrder], [CreatedAt]) VALUES
    ('cat-phones', N'Phones & Tablets', 'phones-tablets', N'Mobile phones and tablets', 1, 1, @SeedDate),
    ('cat-electronics', N'Electronics', 'electronics', N'Electronics and gadgets', 1, 2, @SeedDate),
    ('cat-fashion', N'Fashion', 'fashion', N'Clothing and accessories', 1, 3, @SeedDate),
    ('cat-food', N'Food & Beverage', 'food-beverage', N'Food items and drinks', 1, 4, @SeedDate),
    ('cat-accessories', N'Accessories', 'accessories', N'Accessories and more', 1, 5, @SeedDate),
    ('cat-home', N'Home & Garden', 'home-garden', N'Home and garden items', 1, 6, @SeedDate),
    ('cat-vehicles', N'Vehicles', 'vehicles', N'Cars, bikes and parts', 1, 7, @SeedDate),
    ('cat-health', N'Health & Beauty', 'health-beauty', N'Health and beauty products', 1, 8, @SeedDate),
    ('cat-other', N'Other', 'other', N'Other items', 1, 99, @SeedDate);
END

IF EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('Products') AND name = 'SellerId')
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('Products') AND name = 'CategoryId')
        ALTER TABLE [Products] ADD [CategoryId] nvarchar(450) NULL;
    IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('Products') AND name = 'Condition')
        ALTER TABLE [Products] ADD [Condition] nvarchar(max) NULL;
    IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('Products') AND name = 'Location')
        ALTER TABLE [Products] ADD [Location] nvarchar(200) NULL;
    IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('Products') AND name = 'VendorId')
        ALTER TABLE [Products] ADD [VendorId] nvarchar(450) NULL;
END

GO

-- BATCH 2: Backfill from SellerId only when that column still exists.
-- Uses dynamic SQL so SQL Server does not compile [SellerId] after the column has already been dropped.
IF EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID(N'Products') AND name = N'SellerId')
BEGIN
    EXEC(N'
    UPDATE [Products] SET [VendorId] = [SellerId], [CategoryId] = N''cat-other'', [Condition] = N''New'' WHERE [VendorId] IS NULL;

    ALTER TABLE [Products] DROP CONSTRAINT [FK_Products_Users_SellerId];
    DROP INDEX [IX_Products_SellerId] ON [Products];
    ALTER TABLE [Products] DROP COLUMN [Category];
    ALTER TABLE [Products] DROP COLUMN [SellerId];

    ALTER TABLE [Products] ALTER COLUMN [CategoryId] nvarchar(450) NOT NULL;
    ALTER TABLE [Products] ALTER COLUMN [Condition] nvarchar(max) NOT NULL;
    ALTER TABLE [Products] ALTER COLUMN [VendorId] nvarchar(450) NOT NULL;

    CREATE INDEX [IX_Products_CategoryId] ON [Products] ([CategoryId]);
    CREATE INDEX [IX_Products_VendorId] ON [Products] ([VendorId]);
    ALTER TABLE [Products] ADD CONSTRAINT [FK_Products_ProductCategories_CategoryId] FOREIGN KEY ([CategoryId]) REFERENCES [ProductCategories] ([Id]);
    ALTER TABLE [Products] ADD CONSTRAINT [FK_Products_Users_VendorId] FOREIGN KEY ([VendorId]) REFERENCES [Users] ([Id]) ON DELETE CASCADE;
    ');
END

UPDATE [Users] SET [UserType] = N'Vendor' WHERE [UserType] = N'Seller';

IF NOT EXISTS (SELECT 1 FROM [__EFMigrationsHistory] WHERE [MigrationId] = N'20260215135000_ProductCategoriesAndVendorRename')
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion]) VALUES (N'20260215135000_ProductCategoriesAndVendorRename', N'9.0.0');

COMMIT TRANSACTION;
