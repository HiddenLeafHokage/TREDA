# Where Is the Treda Database?

Your API uses **SQL Server LocalDB** — a lightweight, file-based SQL Server that runs on your PC. The database **TredaDB** is not on a “normal” SQL Server instance you might see in SSMS by default; it’s on the **LocalDB** instance.

---

## 1. What the app is using

From `appsettings.json`:

- **Server:** `(localdb)\mssqllocaldb` → this is the **LocalDB** instance.
- **Database:** `TredaDB` → created automatically when you run `dotnet ef database update`.

So **all “stuff” (users, products, orders, etc.) is saved in the database named TredaDB on LocalDB.**

---

## 2. How to see TredaDB (SQL Server Management Studio – SSMS)

1. Open **SQL Server Management Studio**.
2. In **Connect to Server**:
   - **Server type:** Database Engine  
   - **Server name:** type exactly:
     ```text
     (localdb)\mssqllocaldb
     ```
   - **Authentication:** Windows Authentication  
   - Click **Connect**.
3. In the left **Object Explorer**:
   - Expand **Databases**.
   - You should see **TredaDB** (and maybe `master`, other system DBs).
4. Expand **TredaDB** → **Tables** to see where data is stored (e.g. `Users`, `Products`, `Orders`).

If you don’t see **TredaDB**, the app hasn’t created it yet. Run from the repo (with API stopped):

```bash
cd Backend/API
dotnet ef database update --project ../Persistence
```

Then connect again to `(localdb)\mssqllocaldb` and refresh **Databases**.

---

## 3. How to see TredaDB (Azure Data Studio)

1. Open **Azure Data Studio**.
2. **New connection**:
   - **Server:** `(localdb)\mssqllocaldb`
   - **Authentication:** Windows Auth (or Trusted).
3. Connect, then under **Databases** you’ll see **TredaDB**.

---

## 4. Where is it saved on disk? (optional)

LocalDB stores each database as files in a folder on your machine. You don’t need to touch these; the app and EF use the server name and database name.

Rough location (Windows):

- **Instance folder:**  
  `C:\Users\<YourWindowsUsername>\AppData\Local\Microsoft\Microsoft SQL Server Local DB\Instances\mssqllocaldb\`
- **Database files:**  
  Inside that instance folder you’ll find files like `TredaDB.mdf` (data) and `TredaDB_log.ldf` (log) once the database has been created.

So: **“Where are they saving?”** → In the **TredaDB** database on the **LocalDB** server `(localdb)\mssqllocaldb` (and those files are under your user’s AppData as above).

---

## 5. Quick reference

| What              | Where / How                                      |
|-------------------|--------------------------------------------------|
| Server            | `(localdb)\mssqllocaldb` (LocalDB instance)      |
| Database name     | `TredaDB`                                        |
| See it in SSMS    | Connect to `(localdb)\mssqllocaldb` → Databases  |
| Create/update DB  | `dotnet ef database update --project ../Persistence` from `Backend/API` |
| Config            | `Backend/API/appsettings.json` → `ConnectionStrings:DefaultConnection` |

If you later install full **SQL Server** (e.g. Express) and want to use that instead, you would change the connection string in `appsettings.json` to that server and run the migration again; the same TredaDB schema would be created there.
