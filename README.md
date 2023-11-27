# Setup del proyecto

## Creación del proyecto de Sprint Boot

En Add New Proyecto debemos ingresar la siguiente información

| Información | Valor asingnado |
| --- | --- |
| Name | nombreproyecto |
| Location | ~\Documents |
| Lnaguage | Java* |
| Type | Maven* |
| Group | pe.edu.upc.aaw |
| Artifact | nombreproyecto |
| Package name | pe.edu.upc.aaw.nombreproyecto |
| JDK | corretto-17* |
| Java | 17 |
| Packaging | War |

En la sección de depencias tenemos que **Spring Boot versión 2.7.14** y añadir:

- Spring Boot Dev Tools
- Spring Web
- Spring Data JPA
- PostgreSQL Driver

## Base de datos

Antes de programar, debemos crear la base de datos, para ello seguiremos los siguientes pasos:

1. Entramos a pgAdmin4
2. Expandimos PostgreSQL 15 > Databases
3. Click derecho en Databases
4. Click izquierdo en Create Database
5. Ingresamos el nombre_base_de_datos en el campo Name
6. Click izquierdo en Save

## Propiedades de la aplicación

En *./src/main/java/resources/application.propieties* implementamos las siguientes propiedades para la conección a la base de datos:
```
spring.jpa.database=postgresql
spring.jpa.show-sql=false
spring.jpa.hibernate.ddl-auto=update
spring.datasource.driver-class-name=org.postgresql.Driver
spring.datasource.url=jdbc:postgresql://localhost/NOMBRE_DB #Cambiar por DB creada
spring.datasource.username=postgres
spring.datasource.password=12345678
server.port=8080
spring.jackson.serialization.write-dates-as-timestamps=false
spring.jpa.properties.hibernate.jdbc.lob.non_contextual_creation=true
jwt.secret=4t7w!z%C*F-JaNdRgUkXn2r5u8x/A?D(G+KbPeShVmYq3s6v9y$B&E)H@McQfTjW
spring.devtools.restart.log-condition-evaluation-delta=false
```

## Dependencias

En ./pom.xml se deben inyectar las dependencias springdoc y modelmapper. Ambas mediante el siguiente código:

```
<!-- Security -->
<dependency>
	<groupId>io.jsonwebtoken</groupId>
	<artifactId>jjwt</artifactId>
	<version>0.9.1</version>
</dependency>

<!-- Security -->
<dependency>
	<groupId>org.glassfish.jaxb</groupId>
	<artifactId>jaxb-runtime</artifactId>
</dependency>

<!-- Security -->
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-security</artifactId>
</dependency>

<!-- Swagger -->
<dependency>
	<groupId>org.springdoc</groupId>
	<artifactId>springdoc-openapi-ui</artifactId>
	<version>1.6.4</version>
</dependency>

<!-- ModelMapper (JPA) -->
<dependency>
	<groupId>org.modelmapper</groupId>
	<artifactId>modelmapper</artifactId>
	<version>3.1.1</version>
</dependency>
```

Tras añadir las dependencias debemos ir al panel Maven (ubicado en la barra lateral derecha) y dar click en *Reload Maven Project*

## Correr el codigo en __main__.py

Desde el directorio del repositorio, abrimos una terminal y ejecutamos el siguiente comando:

```bash
py __main__.py
```

## Dar autorizaciones
El código a continuación se utiliza en los controlers de la entidad con el método que se le quiera dar autorización. Se debe usar antes del @Get..., @Post..., @Delete.., @Put... Mapping. Acá el código:
```java
@PreAuthorize("hasAuthority('ADMIN')")
```

## Testing en postman
###### Añadir usuario de test
El primer usuario tipo ADMIN se añade directamente desde PgAdmin. Sus credenciales son:
- Username: `admin`
- Password: `$2a$12$Y21e0xS32N4nQvpsV52M/Obn8KWx4fRSxkT2ERhMjA.kNVkEtYZjW` (admin)
###### Postman login query
- Mapeo: **POST**
- Body: Json
- Body content:  
```json
{
    "username":"admin",
    "password":"admin"
}
```

###### Probar autenticación
Requiere poner en el header del request:
- Key: `Authorization`
- Value: `Bearer [token]` (sin \[\])