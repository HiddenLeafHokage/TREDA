using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Persistence.Migrations;

/// <summary>
/// Adds vendor notifications and traffic analytics tables only (idempotent for existing DBs).
/// </summary>
public partial class VendorNotificationsAndTraffic : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            IF OBJECT_ID(N'[dbo].[VendorNotifications]', N'U') IS NULL
            BEGIN
                CREATE TABLE [dbo].[VendorNotifications] (
                    [Id] nvarchar(450) NOT NULL,
                    [VendorId] nvarchar(450) NOT NULL,
                    [Category] nvarchar(32) NOT NULL,
                    [Title] nvarchar(200) NOT NULL,
                    [Body] nvarchar(2000) NOT NULL,
                    [ActionKind] nvarchar(32) NOT NULL,
                    [RelatedOrderId] nvarchar(max) NULL,
                    [RelatedConversationId] nvarchar(max) NULL,
                    [RelatedProductId] nvarchar(max) NULL,
                    [IsRead] bit NOT NULL,
                    [ReadAt] datetime2 NULL,
                    [CreatedAt] datetime2 NOT NULL,
                    CONSTRAINT [PK_VendorNotifications] PRIMARY KEY ([Id]),
                    CONSTRAINT [FK_VendorNotifications_Users_VendorId] FOREIGN KEY ([VendorId]) REFERENCES [Users] ([Id]) ON DELETE CASCADE
                );
                CREATE INDEX [IX_VendorNotifications_CreatedAt] ON [dbo].[VendorNotifications] ([CreatedAt]);
                CREATE INDEX [IX_VendorNotifications_VendorId_Category] ON [dbo].[VendorNotifications] ([VendorId], [Category]);
                CREATE INDEX [IX_VendorNotifications_VendorId_IsRead] ON [dbo].[VendorNotifications] ([VendorId], [IsRead]);
            END

            IF OBJECT_ID(N'[dbo].[VendorTrafficEvents]', N'U') IS NULL
            BEGIN
                CREATE TABLE [dbo].[VendorTrafficEvents] (
                    [Id] nvarchar(450) NOT NULL,
                    [VendorId] nvarchar(450) NOT NULL,
                    [EventType] nvarchar(32) NOT NULL,
                    [ProductId] nvarchar(max) NULL,
                    [SearchTerm] nvarchar(500) NULL,
                    [CreatedAt] datetime2 NOT NULL,
                    CONSTRAINT [PK_VendorTrafficEvents] PRIMARY KEY ([Id])
                );
                CREATE INDEX [IX_VendorTrafficEvents_CreatedAt] ON [dbo].[VendorTrafficEvents] ([CreatedAt]);
                CREATE INDEX [IX_VendorTrafficEvents_VendorId_EventType_CreatedAt] ON [dbo].[VendorTrafficEvents] ([VendorId], [EventType], [CreatedAt]);
            END
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            IF OBJECT_ID(N'[dbo].[VendorNotifications]', N'U') IS NOT NULL
                DROP TABLE [dbo].[VendorNotifications];
            IF OBJECT_ID(N'[dbo].[VendorTrafficEvents]', N'U') IS NOT NULL
                DROP TABLE [dbo].[VendorTrafficEvents];
            """);
    }
}
