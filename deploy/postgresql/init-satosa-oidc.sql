-- Banco do frontend OIDC do SATOSA. Fica separado do banco do cuidapp ("postgres")
-- porque os dois usam Alembic, e a tabela alembic_version de um sobrescreveria a do
-- outro. Executado só na primeira inicialização do volume.
CREATE DATABASE satosa_oidc;
