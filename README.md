# authn_oidc

[![Build Status](https://github.com/icatproject/authn.oidc/workflows/CI%20Build/badge.svg?branch=master)](https://github.com/icatproject/authn.oidc/actions?query=workflow%3A%22CI+Build%22)

This project uses Quarkus, a Java Framework. <https://quarkus.io/>

## Running the application in dev mode

You can run this application locally in dev mode that enables live coding using:

```shell script
./mvnw compile quarkus:dev
```
> **_NOTE:_**  Quarkus also ships with a Dev UI, which is available in dev mode only at <http://localhost:8080/q/dev/>.

## List of endpoints

| Location        | Example                                                                                                 | Successful Results                        |
|-----------------|---------------------------------------------------------------------------------------------------------|-------------------------------------------|
| `/version`      | `curl http://localhost:8080/authn.oidc/version`                                                         | `{"version":"4.0.0"}`                     |
| `/description`  | `curl http://localhost:8080/authn.oidc/description `                                                    | `{"keys":[{"name":"token","hide":true}]}` |
| `/authenticate` | `curl -d json='{"credentials":[{"token":"validToken"}]}' http://localhost:8080/authn.oidc/authenticate` | `{"username":"name"}`                     |

## Packaging and running the application

The application can be packaged using:

```shell script
./mvnw clean package -DskipTests
```

It produces the `.jar` file in the `target/` directory.
Be aware that it’s not a _über-jar_ as the dependencies are copied into the `target/quarkus-app/lib/` directory.

## Testing

The application uses integration tests to fully verify the api endpoints. The package needs to be built above first.

An instance of Keycloak is needed with some test data in it. This is initiated from `src/test/realm-config`.

```shell script
# this will start a local Keycloak instance with some dummy data in it to test against
docker compose up
```
then the tests can be run:

```shell script
./mvnw failsafe:integration-test
```

The application can be run using:

```shell script
java -jar target/quarkus-app/quarkus-run.jar
```

If you want to build a [_über-jar_](https://blog.payara.fish/what-is-a-java-uber-jar), execute the following command:

```shell script
./mvnw package -DskipTests -Dquarkus.package.jar.type=uber-jar
```

The application, packaged as a _über-jar_, is now runnable using `java -jar target/*-runner.jar`.

## Creating a native executable

You can create a [native](https://quarkus.io/guides/building-native-image#producing-a-native-executable) executable using docker by:

```shell script
./mvnw package -DskipTests -Dnative -Dquarkus.native.container-build=true
```

You can then execute the native executable with: `./target/*-runner`

## Docker :whale:

Once these packages have been built, they can be copied into a container and run.

Various dockerfiles exist in the `src/main/docker` folder to facilitate this.

For example, to build a native docker image locally:

```shell script
# from the root folder
docker build -f src/main/docker/Dockerfile.native -t quarkus/qarkus_auth
```

Then the image can be run:

```shell script
docker run -i --rm -p 8080:8080 quarkus/qarkus_auth
```
## CI:
Integration tests are run automatically as part of the CI build. If successful, a Docker image is automatically pushed to STFC's Harbor Repo.
It can be run by:

```shell script
docker run -p 8080:8080 harbor.stfc.ac.uk/icat/authn_oidc:<git branch name>
```




