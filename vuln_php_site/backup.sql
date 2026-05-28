-- Vulnerable PHP site demo backup
CREATE TABLE users (
  id INT PRIMARY KEY,
  username VARCHAR(50),
  password VARCHAR(255)
);

INSERT INTO users (id, username, password) VALUES
  (1, 'admin', 'admin123'),
  (2, 'guest', 'guest123');
