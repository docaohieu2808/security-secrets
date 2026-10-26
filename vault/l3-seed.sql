-- Loaded once by the postgres container: a table for the dynamic roles' GRANT ... ON ALL TABLES to act on.
CREATE TABLE IF NOT EXISTS orders (id serial PRIMARY KEY, item text NOT NULL);
INSERT INTO orders (item) VALUES ('example item');
