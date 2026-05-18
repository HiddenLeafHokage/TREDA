-- Add guest buyer support: nullable BuyerId/SenderId, GuestEmail, GuestName, etc.
-- Run against TredaDB when you have the new code. Stop the API first.

BEGIN TRANSACTION;

-- Orders: add guest columns, make BuyerId nullable
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('Orders') AND name = 'GuestEmail')
    ALTER TABLE [Orders] ADD [GuestEmail] nvarchar(256) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('Orders') AND name = 'GuestName')
    ALTER TABLE [Orders] ADD [GuestName] nvarchar(200) NULL;

-- Make BuyerId nullable and FK optional (drop and re-add)
IF EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_Orders_Users_BuyerId')
    ALTER TABLE [Orders] DROP CONSTRAINT [FK_Orders_Users_BuyerId];
IF EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('Orders') AND name = 'BuyerId')
    ALTER TABLE [Orders] ALTER COLUMN [BuyerId] nvarchar(450) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_Orders_Users_BuyerId')
    ALTER TABLE [Orders] ADD CONSTRAINT [FK_Orders_Users_BuyerId] FOREIGN KEY ([BuyerId]) REFERENCES [Users] ([Id]) ON DELETE SET NULL;

-- Conversations: add guest columns, make BuyerId nullable
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('Conversations') AND name = 'GuestEmail')
    ALTER TABLE [Conversations] ADD [GuestEmail] nvarchar(256) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('Conversations') AND name = 'GuestName')
    ALTER TABLE [Conversations] ADD [GuestName] nvarchar(200) NULL;

IF EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_Conversations_Users_BuyerId')
    ALTER TABLE [Conversations] DROP CONSTRAINT [FK_Conversations_Users_BuyerId];
IF EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('Conversations') AND name = 'BuyerId')
    ALTER TABLE [Conversations] ALTER COLUMN [BuyerId] nvarchar(450) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_Conversations_Users_BuyerId')
    ALTER TABLE [Conversations] ADD CONSTRAINT [FK_Conversations_Users_BuyerId] FOREIGN KEY ([BuyerId]) REFERENCES [Users] ([Id]) ON DELETE SET NULL;

-- Messages: add guest sender columns, make SenderId nullable
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('Messages') AND name = 'GuestSenderEmail')
    ALTER TABLE [Messages] ADD [GuestSenderEmail] nvarchar(256) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('Messages') AND name = 'GuestSenderName')
    ALTER TABLE [Messages] ADD [GuestSenderName] nvarchar(200) NULL;

IF EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_Messages_Users_SenderId')
    ALTER TABLE [Messages] DROP CONSTRAINT [FK_Messages_Users_SenderId];
IF EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('Messages') AND name = 'SenderId')
    ALTER TABLE [Messages] ALTER COLUMN [SenderId] nvarchar(450) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_Messages_Users_SenderId')
    ALTER TABLE [Messages] ADD CONSTRAINT [FK_Messages_Users_SenderId] FOREIGN KEY ([SenderId]) REFERENCES [Users] ([Id]) ON DELETE SET NULL;

COMMIT TRANSACTION;
