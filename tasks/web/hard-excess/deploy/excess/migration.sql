drop table if exists authors;
create table if not exists authors (
    name      text  primary key not null,
    password  text  not null
);

drop table if exists messages;
create table if not exists messages (
    id       text  primary key not null,
    author   text  not null,
    title    text  not null,
    content  text  not null
);
