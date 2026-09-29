-- Roda automaticamente na PRIMEIRA vez que o container do PostgreSQL cria o banco
-- (o docker-compose.yml monta este arquivo em /docker-entrypoint-initdb.d).
-- Cria um segundo banco, só para os testes: eles apagam e recriam as tabelas a cada
-- execução, e não podem mexer nos dados do banco de desenvolvimento.
CREATE DATABASE pwncheck_test;
