using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MailArchiver.Migrations
{
    /// <inheritdoc />
    public partial class MigrateV2602_3 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Add FraudStatus column to ArchivedEmails table
            migrationBuilder.Sql(@"
                DO $$ 
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 
                        FROM information_schema.columns 
                        WHERE table_schema = 'mail_archiver' 
                        AND table_name = 'ArchivedEmails' 
                        AND column_name = 'FraudStatus'
                    ) THEN
                        ALTER TABLE mail_archiver.""ArchivedEmails"" ADD COLUMN ""FraudStatus"" integer NOT NULL DEFAULT 0;
                    END IF;
                END $$;
            ");

            migrationBuilder.Sql(@"
                COMMENT ON COLUMN mail_archiver.""ArchivedEmails"".""FraudStatus"" IS 'Fraud classification: 0=Normal, 1=Suspicious, 2=Fraud';
            ");

            // Add FraudDetails column to ArchivedEmails table
            migrationBuilder.Sql(@"
                DO $$ 
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 
                        FROM information_schema.columns 
                        WHERE table_schema = 'mail_archiver' 
                        AND table_name = 'ArchivedEmails' 
                        AND column_name = 'FraudDetails'
                    ) THEN
                        ALTER TABLE mail_archiver.""ArchivedEmails"" ADD COLUMN ""FraudDetails"" text;
                    END IF;
                END $$;
            ");

            migrationBuilder.Sql(@"
                COMMENT ON COLUMN mail_archiver.""ArchivedEmails"".""FraudDetails"" IS 'Details about why this email was classified as fraud or suspicious';
            ");

            // Add index on FraudStatus for efficient filtering
            migrationBuilder.Sql(@"
                DO $$ 
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_indexes 
                        WHERE schemaname = 'mail_archiver' 
                        AND indexname = 'IX_ArchivedEmails_FraudStatus'
                    ) THEN
                        CREATE INDEX ""IX_ArchivedEmails_FraudStatus"" ON mail_archiver.""ArchivedEmails"" (""FraudStatus"");
                    END IF;
                END $$;
            ");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Remove index
            migrationBuilder.Sql(@"
                DO $$ 
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM pg_indexes 
                        WHERE schemaname = 'mail_archiver' 
                        AND indexname = 'IX_ArchivedEmails_FraudStatus'
                    ) THEN
                        DROP INDEX mail_archiver.""IX_ArchivedEmails_FraudStatus"";
                    END IF;
                END $$;
            ");

            // Remove FraudDetails column
            migrationBuilder.Sql(@"
                DO $$ 
                BEGIN
                    IF EXISTS (
                        SELECT 1 
                        FROM information_schema.columns 
                        WHERE table_schema = 'mail_archiver' 
                        AND table_name = 'ArchivedEmails' 
                        AND column_name = 'FraudDetails'
                    ) THEN
                        ALTER TABLE mail_archiver.""ArchivedEmails"" DROP COLUMN ""FraudDetails"";
                    END IF;
                END $$;
            ");

            // Remove FraudStatus column
            migrationBuilder.Sql(@"
                DO $$ 
                BEGIN
                    IF EXISTS (
                        SELECT 1 
                        FROM information_schema.columns 
                        WHERE table_schema = 'mail_archiver' 
                        AND table_name = 'ArchivedEmails' 
                        AND column_name = 'FraudStatus'
                    ) THEN
                        ALTER TABLE mail_archiver.""ArchivedEmails"" DROP COLUMN ""FraudStatus"";
                    END IF;
                END $$;
            ");
        }
    }
}
