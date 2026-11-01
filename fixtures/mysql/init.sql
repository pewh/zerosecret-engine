CREATE USER 'zs_sha2'@'%' IDENTIFIED WITH caching_sha2_password BY 'zs-test-sha2-password';
CREATE USER 'zs_native'@'%' IDENTIFIED WITH mysql_native_password BY 'zs-test-native-password';
ALTER USER 'root'@'%' IDENTIFIED WITH mysql_native_password BY 'zs-test-root';
