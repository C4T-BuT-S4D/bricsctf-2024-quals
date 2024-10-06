# BRICS+ CTF 2024 | excess

## Description

> Untrust Us.

## Public archive

- [public/excess.tar.gz](public/excess.tar.gz)

## Deploy

```
cd deploy && docker compose up --build -d
```

## Solution

Let's describe some milestones.

### Client

Client-side problems are straightforward:

#### 1. prototype pollution

There is obvious prototype pollution in `Context.ContextProvider`:

[Context/index.tsx](src/client/src/Context/index.tsx)

```ts
const context: any = { name, setName };
const previous: string = decodeURIComponent(window.location.hash.slice(1));

JSON.parse(previous || "[]").map(([x, y, z]: any[]) => context[x][y] = z);
```

So we can control `location.hash` value and arbitrary pollute object.

#### 2. HTML insertion

`ViewMessage` page downloads html from the server and inserts it using `dangerouslySetInnerHTML`.

[components/pages/ViewMessagePage/index.tsx](src/client/src/components/pages/ViewMessagePage/index.tsx)

```
return (
    <div className='ViewMessagePage'>
        <div className='ViewMessagePage-Header'>
            <span className='ViewMessagePage-Title'>Excess | Message</span>
        </div>
        <div className='ViewMessagePage-Container'>
            <Error error={error}/>
            <div className='ViewMessagePage-Message' dangerouslySetInnerHTML={{__html: html}}></div>
            <div className='ViewMessagePage-Buttons'>
                <Button onClick={backClickHandler} id='back' text='Back'/>
            </div>
        </div>
    </div>
);
```

### Server

The server handles API exceptions using custom exception handler.

[server/api.cpp](src/server/server/api.cpp):

```cpp
void Api::HandleException(const httplib::Request& req, httplib::Response& res, const std::exception_ptr ptr) {
    std::string error;

    try {
        std::rethrow_exception(ptr);
    } catch (const BadRequestError& ex) {
        error = ex.what();
        res.status = httplib::StatusCode::BadRequest_400;
    } catch (const Storage::MessageAlreadyExistsError& ex) {
        error = ex.what();
        res.status = httplib::StatusCode::Conflict_409;
    } catch (const Services::InvalidSessionError& ex) {
        error = ex.what();
        res.status = httplib::StatusCode::Unauthorized_401;
    } catch (const Services::InvalidCredentialsError& ex) {
        error = ex.what();
        res.status = httplib::StatusCode::Unauthorized_401;
    } catch (const Services::MessageNotFoundError& ex) {
        error = ex.what();
        res.status = httplib::StatusCode::NotFound_404;
    } catch (const std::exception& ex) {
        error = ex.what();
    }

    nlohmann::json result = {
        {"error", error},
    };

    res.set_content(result.dump(), JsonContentType);
}
```

But there are two problems:

#### 1. missing exception

During registration the server checks if the new author already exists.

[storage/sqlite_storage.cpp](src/server/storage/sqlite_storage.cpp)

```cpp
void SqliteStorage::CreateAuthor(const Models::Author& author) {
    auto sql = "insert into authors (name, password) values (?, ?)"s;

    try {
        ExecuteSql(sql, { author.GetName(), author.GetPassword() });
    } catch (const SqliteConflictError&) {
        throw AuthorAlreadyExistsError("author " + author.GetName() + " already exists"s);
    }
}
```

But `AuthorAlreadyExistsError` has no `catch` clause for itself. Instead it will be proceed as `std::exception` default clause. Note that it doesn't set `res.status`, so it would be 200_OK.

#### 2. unhandled exception

What if another exception occured during handling the exception? Then function `Api::HandleException` will throw this exception and server will crash. Note that there is no check for JSON exceptions.

```cpp
nlohmann::json result = {
    {"error", error},
};

res.set_content(result.dump(), JsonContentType);
```

So if JSON will throw the exception the server will crash.

### Exploitation

1. Use prototype pollution to pollute `headers` and `method` fields of object. It leads to control `fetch()` parameters object and allows us to perform any request.

2. Use `Range: bytes=17-` header in order to download a part of returned JSON. Basically if the server set `res.status` it's not possible, but on `AuthorAlreadyExistsError` exception `res.status` is not set and range header will be applied

3. Use XS-leak to exfiltrate flag. CSP blocks inline javascript, so we can't use `<script>`, but we still can insert HTML. Use object with lazy loading fallback.

```html
<object data='URL'>
    <img src='FALLBACK_URL' loading='lazy'>
</object>
```

If call to `URL` returns error then `FALLBACK_URL` will be called. If `URL` returns 200 OK there won't be any call to `FALLBACK_URL`.

4. Throw unhandled exception if prefix is not correct. Set `URL` to `/messages?content=<prefix>` and `FALLBACK_URL` to `/message/%ff`. JSON will throw an exception during `\xff` serialization, it leads to server downtime.

5. Track server downtime from internet. We know public URL so we can easily perform many requests and check is the server down.

So the final chain:

```
1. pollute fetch headers
2. conflict on /register -> html inserted on the page
3. call to /messages?content=<prefix> with fallback to /message/%ff
4. check if the server is crashed
```

Example solver: [solution/exploit.html](solution/exploit.html)
