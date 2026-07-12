create table if not exists users(
    id bigint generated always as identity primary key,
    email text not null unique,
    pass_hash text not null,
    is_admin boolean not null default false,
    created_at timestamptz not null default now()
);