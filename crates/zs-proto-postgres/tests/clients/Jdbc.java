import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;
import java.util.regex.Pattern;

public class Jdbc {
    static final boolean READ_ONLY = "read_only".equals(System.getenv("ZS_CLIENT_ACCESS"));
    static final String TABLE = System.getenv("ZS_CLIENT_TABLE");
    static final Pattern MODE = Pattern.compile("read[-_ ]only", Pattern.CASE_INSENSITIVE);
    static boolean failed = false;

    static void write(Statement statement, String step, String sql) {
        try {
            statement.execute(sql);
            if (READ_ONLY) {
                System.out.println(step + ": FAIL succeeded");
                failed = true;
            } else {
                System.out.println(step + ": ok");
            }
        } catch (SQLException error) {
            String message = String.valueOf(error.getMessage()).split("\n")[0];
            if (READ_ONLY && MODE.matcher(message).find()) {
                System.out.println(step + ": refused " + error.getSQLState() + " " + message);
            } else {
                System.out.println(step + ": FAIL " + message);
                failed = true;
            }
        }
    }

    static void read(Statement statement, String step, long expected) {
        try (ResultSet rows = statement.executeQuery("SELECT count(*) FROM " + TABLE)) {
            rows.next();
            long count = rows.getLong(1);
            if (count == expected) {
                System.out.println(step + ": ok rows=" + count);
            } else {
                System.out.println(step + ": FAIL rows=" + count);
                failed = true;
            }
        } catch (SQLException error) {
            System.out.println(step + ": FAIL " + error.getMessage());
            failed = true;
        }
    }

    public static void main(String[] args) throws Exception {
        String url = "jdbc:postgresql://" + System.getenv("ZS_CLIENT_HOST") + ":" + System.getenv("ZS_CLIENT_PORT")
                + "/" + System.getenv("ZS_CLIENT_DB");
        Properties properties = new Properties();
        properties.setProperty("user", System.getenv("ZS_CLIENT_USER"));
        properties.setProperty("sslmode", "disable");
        try (Connection connection = DriverManager.getConnection(url, properties);
                Statement statement = connection.createStatement()) {
            read(statement, "read", 1);
            write(statement, "write", "INSERT INTO " + TABLE + " VALUES (2)");
            write(statement, "switch-off", "SET default_transaction_read_only = off");
            write(statement, "write-after-switch-off", "INSERT INTO " + TABLE + " VALUES (3)");
            read(statement, "read-after", READ_ONLY ? 1 : 3);
        }
        Properties always = new Properties();
        always.putAll(properties);
        always.setProperty("readOnlyMode", "always");
        try (Connection connection = DriverManager.getConnection(url, always)) {
            connection.setReadOnly(true);
            connection.setReadOnly(false);
            System.out.println("fact set-read-write: ok");
        } catch (SQLException error) {
            System.out.println("fact set-read-write: " + String.valueOf(error.getMessage()).split("\n")[0]);
        }
        System.exit(failed ? 1 : 0);
    }
}
