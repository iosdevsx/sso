create table if not exists login_attempts(
    user_id bigint not null primary key references users(id) on delete cascade,
    count bigint not null default 1,
    locked_until timestamptz
)