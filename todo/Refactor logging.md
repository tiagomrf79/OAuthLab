I don't like how the logs are polluting the remaining code in `HomeController.cs`.

We could register an `HttpClient` handler and a middleware to move this code out and log automatically.

TBD as we might end up using a different logging approach using a message broker.
