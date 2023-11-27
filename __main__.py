import os

### Entity format (data type can be String, boolean, Long, int, double, or LocalDate).
### Attribute names are always lower case except
### Dont write the id attribute, it is generated automatically
"""
entities = [
    {
        "entityName": "<Entity name>",
        "attributes": [
            ["<Data Type>", "<attribute name>"],
            ["<Foreign entity name>", "<foreign entity name>"], # Many to one
            # Add more attributes as needed
        ],
    },
    # Add more entities as needed
]
"""
### Example entities
"""
entities = [
    {
        "entityName": "Dessert",
        "attributes": [
            ["String", "name"],
            ["int", "preparation"],
            ["String", "difficulty"],
        ],
    },
    {
        "entityName": "Ingredient",
        "attributes": [
            ["String", "name"],
            ["int", "quantity"],
            ["Dessert", "dessert"],
        ],
    },
]
"""
### My entities
"""
Dessert
=======
private Int idDessert
private String name
private int preparation
private String difficulty
Ingredient
=========
private Int idIngredient
private String name
private int quantity
IdDessert clave foránea

"""

useSecurity = True
projectName = 'api_ef_2'
entities = [
    {
        "entityName": "Dessert",
        "attributes": [
            ["String", "name"],
            ["int", "preparation"],
            ["String", "difficulty"],
        ],
    },
    {
        "entityName": "Ingredient",
        "attributes": [
            ["String", "name"],
            ["int", "quantity"],
            ["Dessert", "dessert"],
        ],
    },
]

# Generates the entity file
def generateEntityFile(projectName, entityName, attributes):
    content = ''
    # Generate imports and package
    content += f'package pe.edu.upc.aaw.{projectName}.entities;\n\n'
    content += 'import javax.persistence.*;\n'
    content += f'import pe.edu.upc.aaw.{projectName}.entities.*;\n'
    content += 'import java.time.LocalDate;\n\n'

    content += f'@Entity\n@Table(name = \"{entityName.capitalize()}\")\npublic class {entityName.capitalize()} {{\n\n'
    content += '@Id\n'
    content += '@GeneratedValue(strategy = GenerationType.IDENTITY)\n'
    content += f'private int id{entityName.capitalize()};\n\n'
    for attribute in attributes:
        # if attribute is tipe LocalDate, int, double, String or boolean
        if attribute[0] == 'LocalDate' or attribute[0] == 'int' or attribute[0] == 'double' or attribute[0] == 'String' or attribute[0] == 'boolean':
            content += f'@Column(name = "{attribute[1]}", nullable = false)\n'
            content += f'private {attribute[0]} {attribute[1]};\n\n'

        # if attribute is a foreign key
        else:
            content += f'@ManyToOne\n'
            content += f'@JoinColumn(name = "id{attribute[1].capitalize()}")\n'
            content += f'private {attribute[0]} {attribute[1]};\n\n'
            
    # Generate empty constructor
    content += f'public {entityName.capitalize()}() {{ }}\n\n'

    # Generate constructor (for attributes, including ID)
    content += f'public {entityName.capitalize()}('
    content += f'int id{entityName.capitalize()},'
    for attribute in attributes:
        content += f'{attribute[0]} {attribute[1]}, '
    content = content[:-2]
    content += ') {\n'
    content += f'    this.id{entityName.capitalize()} = id{entityName.capitalize()};\n'
    for attribute in attributes:
        content += f'    this.{attribute[1]} = {attribute[1]};\n'
    content += '}\n\n'

    # Generate getters and setters (for attributes, including ID)
    # ID
    content += f'public int getId{entityName.capitalize()}() {{\n'
    content += f'    return id{entityName.capitalize()};\n'
    content += '}\n\n'
    content += f'public void setId{entityName.capitalize()}(int id{entityName.capitalize()}) {{\n'
    content += f'    this.id{entityName.capitalize()} = id{entityName.capitalize()};\n'
    content += '}\n\n'
    # Attributes
    for attribute in attributes:
        content += f'public {attribute[0]} get{attribute[1].capitalize()}() {{\n'
        content += f'    return {attribute[1]};\n'
        content += '}\n\n'
        content += f'public void set{attribute[1].capitalize()}({attribute[0]} {attribute[1]}) {{\n'
        content += f'    this.{attribute[1]} = {attribute[1]};\n'
        content += '}\n\n'
    content += '}'

    # Create a folder called ProjectName/Entities
    if not os.path.exists(f'testenv/{projectName}/entities'):
        os.makedirs(f'testenv/{projectName}/entities')

    # Create a txt file, write the data and close it. In a folder called ProjectName/Entities
    f = open(f'testenv/{projectName}/entities/{entityName.capitalize()}.java', 'w')
    f.write(content)    
    f.close()

# Generates the repository file
def generateRepositoryFile(projectName, entityName):
    content = ''
    # Generate imports and package
    content += f'package pe.edu.upc.aaw.{projectName}.repositories;\n\n'
    content += 'import org.springframework.data.jpa.repository.JpaRepository;\n'
    content += 'import org.springframework.stereotype.Repository;\n'
    content += f'import pe.edu.upc.aaw.{projectName}.entities.{entityName.capitalize()};\n'
    content += 'import java.util.List;\n\n'

    content += f'@Repository\npublic interface I{entityName.capitalize()}Repository extends JpaRepository<{entityName.capitalize()}, Integer> {{ }}'

    # Create a folder called ProjectName/Repositories
    if not os.path.exists(f'testenv/{projectName}/repositories'):
        os.makedirs(f'testenv/{projectName}/repositories')

    # Create a txt file, write the data and close it. In a folder called ProjectName/Repositories
    f = open(f'testenv/{projectName}/repositories/I{entityName.capitalize()}Repository.java', 'w')
    f.write(content)
    f.close()

# Generates the service interface file
def generateServiceInterface(projectName, entityName):
    content = ''
    # Generate imports and package
    content += f'package pe.edu.upc.aaw.{projectName}.serviceinterfaces;\n\n'
    content += f'import pe.edu.upc.aaw.{projectName}.entities.{entityName.capitalize()};\n'
    content += 'import java.util.List;\n\n'

    content += f'public interface I{entityName.capitalize()}Service {{\n'
    content += f'    void insert({entityName.capitalize()} {entityName});\n'
    content += f'    void delete(int id);\n'
    content += f'    {entityName.capitalize()} listId(int id);\n'
    content += f'    List<{entityName.capitalize()}> list();\n'
    content += '}'

    # Create a folder called ProjectName/serviceinterfaces
    if not os.path.exists(f'testenv/{projectName}/serviceinterfaces'):
        os.makedirs(f'testenv/{projectName}/serviceinterfaces')

    # Create a txt file, write the data and close it. In a folder called ProjectName/serviceinterfaces
    f = open(f'testenv/{projectName}/serviceinterfaces/I{entityName.capitalize()}Service.java', 'w')
    f.write(content)
    f.close()

# Generates the service implement file
def generateServiceImplement(projectName, entityName):
    content = ''
    # Generate imports and package
    content += f'package pe.edu.upc.aaw.{projectName}.serviceimplements;\n\n'
    content += 'import org.springframework.beans.factory.annotation.*;\n'
    content += 'import org.springframework.stereotype.*;\n'
    content += f'import pe.edu.upc.aaw.{projectName}.entities.{entityName.capitalize()};\n'
    content += f'import pe.edu.upc.aaw.{projectName}.repositories.I{entityName.capitalize()}Repository;\n'
    content += f'import pe.edu.upc.aaw.{projectName}.serviceinterfaces.I{entityName.capitalize()}Service;\n\n'

    content += 'import java.util.List;\n\n'

    content += f'@Service\npublic class {entityName.capitalize()}ServiceImplement implements I{entityName.capitalize()}Service {{\n'
    content += f'    @Autowired\n'
    content += f'    private I{entityName.capitalize()}Repository myRepository;\n\n'
    
    # Add an item to table
    content += f'    // Add an item to table\n'
    content += f'    @Override\n'
    content += f'    public void insert({entityName.capitalize()} {entityName}) {{\n'
    content += f'        myRepository.save({entityName});\n'
    content += f'    }}\n\n'

    # Delete an item by ID on table
    content += f'    // Delete an item by ID on table\n'
    content += f'    @Override\n'
    content += f'    public void delete(int id{entityName.capitalize()}){{\n'
    content += f'        myRepository.deleteById(id{entityName.capitalize()});\n'
    content += f'    }}\n\n'

    # Retrieve an items by ID from table
    content += f'    // Retrieve an items by ID from table\n'
    content += f'    @Override\n'
    content += f'    public {entityName.capitalize()} listId(int id{entityName.capitalize()}){{\n'
    content += f'        return myRepository.findById(id{entityName.capitalize()}).orElse(new {entityName.capitalize()}());\n'
    content += f'    }}\n\n'

    # Retrieve all items from table
    content += f'    // Retrieve all items from table\n'
    content += f'    @Override\n'
    content += f'    public List<{entityName.capitalize()}> list() {{\n'
    content += f'        return myRepository.findAll();\n'
    content += f'    }}\n'
    content += '}'

    # Create a folder called ProjectName/serviceimplements
    if not os.path.exists(f'testenv/{projectName}/serviceimplements'):
        os.makedirs(f'testenv/{projectName}/serviceimplements')

    # Create a txt file, write the data and close it. In a folder called ProjectName/serviceimplements
    f = open(f'testenv/{projectName}/serviceimplements/{entityName.capitalize()}ServiceImplement.java', 'w')
    f.write(content)
    f.close()

# Generates the DTO file
def generateDTO(projectName, entityName, attributes):
    content = ''
    # Generate imports and package
    content += f'package pe.edu.upc.aaw.{projectName}.dtos;\n\n'
    content += f'import pe.edu.upc.aaw.{projectName}.entities.*;\n'
    content += 'import java.time.LocalDate;\n\n'

    content += f'public class {entityName.capitalize()}DTO {{\n'

    # Generates id attribute
    content += f'    private int id{entityName.capitalize()};\n'

    # Generate attributes
    for attribute in attributes:
        content += f'    private {attribute[0]} {attribute[1]};\n'
    content += '\n'

    # Generate id attribute getter and setter
    content += f'    public int getId{entityName.capitalize()}() {{\n'
    content += f'        return id{entityName.capitalize()};\n'
    content += '    }\n\n'
    content += f'    public void setId{entityName.capitalize()}(int id{entityName.capitalize()}) {{\n'
    content += f'        this.id{entityName.capitalize()} = id{entityName.capitalize()};\n'
    content += '    }\n\n'

    # Generate attributes getters and setters
    for attribute in attributes:
        content += f'    public {attribute[0]} get{attribute[1].capitalize()}() {{\n'
        content += f'        return {attribute[1]};\n'
        content += '    }\n\n'
        content += f'    public void set{attribute[1].capitalize()}({attribute[0]} {attribute[1]}) {{\n'
        content += f'        this.{attribute[1]} = {attribute[1]};\n'
        content += '    }\n\n'
    content += '}'

    # Create a folder called ProjectName/dtos
    if not os.path.exists(f'testenv/{projectName}/dtos'):
        os.makedirs(f'testenv/{projectName}/dtos')

    # Create a txt file, write the data and close it. In a folder called ProjectName/dtos
    f = open(f'testenv/{projectName}/dtos/{entityName.capitalize()}DTO.java', 'w')
    f.write(content)
    f.close()

# Generates the controller file
def generateController(projectName, entityName):
    content = ''
    # Generate imports and package
    content += f'package pe.edu.upc.aaw.{projectName}.controllers;\n\n'
    content += 'import org.modelmapper.ModelMapper;\n'
    content += 'import org.springframework.beans.factory.annotation.Autowired;\n'
    content += 'import org.springframework.web.bind.annotation.*;\n'
    content += f'import pe.edu.upc.aaw.{projectName}.dtos.{entityName.capitalize()}DTO;\n'
    content += f'import pe.edu.upc.aaw.{projectName}.entities.{entityName.capitalize()};\n'
    content += f'import pe.edu.upc.aaw.{projectName}.serviceinterfaces.I{entityName.capitalize()}Service;\n\n'

    content += 'import java.util.List;\n'
    content += 'import java.util.stream.Collectors;\n\n'

    content += f'@RestController\n'
    content += f'@CrossOrigin(origins = "http://localhost:4200")\n'
    content += f'@RequestMapping("/{entityName.lower()}")\n'
    content += f'public class {entityName.capitalize()}Controller {{\n'
    content += f'    @Autowired\n'
    content += f'    private I{entityName.capitalize()}Service myService;\n\n'

    # Add an item to table
    content += f'    // Add an item to table\n'
    content += f'    @PostMapping\n'
    content += f'    public void registrar(@RequestBody {entityName.capitalize()}DTO dto) {{\n'
    content += f'        ModelMapper m = new ModelMapper();\n'
    content += f'        {entityName.capitalize()} myItem = m.map(dto, {entityName.capitalize()}.class);\n'
    content += f'        myService.insert(myItem);\n'
    content += f'    }}\n\n'

    # Delete an item by ID on table
    content += f'    // Delete an item by ID on table\n'
    content +=  '    @DeleteMapping("/{id}")\n'
    content += f'    public void eliminar(@PathVariable("id")Integer id){{\n'
    content += f'        myService.delete(id);\n'
    content += f'    }}\n\n'

    # Retrieve an items by ID from table
    content += f'    // Retrieve an items by ID from table\n'
    content +=  '    @GetMapping("/{id}")\n'

    content += f'    public {entityName.capitalize()}DTO listarId(@PathVariable("id")Integer id){{\n'
    content += f'        ModelMapper m = new ModelMapper();\n'
    content += f'        {entityName.capitalize()}DTO myItem = m.map(myService.listId(id), {entityName.capitalize()}DTO.class);\n'
    content += f'        return myItem;\n'
    content += f'    }}\n\n'

    # Retrieve all items from table
    content += f'    // Retrieve all items from table\n'
    content += f'    @GetMapping\n'
    content += f'    public List<{entityName.capitalize()}DTO> listar(){{\n'
    content += f'        return myService.list().stream().map(x -> {{\n'
    content += f'            ModelMapper m = new ModelMapper();\n'
    content += f'            return m.map(x, {entityName.capitalize()}DTO.class);\n'
    content += f'        }}).collect(Collectors.toList());\n'
    content += f'    }}\n\n'

    # (Exclusive to controller) Modify values on table
    content += f'    // (Exclusive to controller) Modify values on table\n'
    content += f'    @PutMapping\n'
    content += f'    public void modificar(@RequestBody {entityName.capitalize()}DTO dto) {{\n'
    content += f'        ModelMapper m = new ModelMapper();\n'
    content += f'        {entityName.capitalize()} d = m.map(dto, {entityName.capitalize()}.class);\n'
    content += f'        myService.insert(d);\n'
    content += f'    }}\n'
    content += '}'

    # Create a folder called ProjectName/controllers
    if not os.path.exists(f'testenv/{projectName}/controllers'):
        os.makedirs(f'testenv/{projectName}/controllers')

    # Create a txt file, write the data and close it. In a folder called ProjectName/controllers
    f = open(f'testenv/{projectName}/controllers/{entityName.capitalize()}Controller.java', 'w')
    f.write(content)
    f.close()

# Generates the CORS util
def generateUtilForCORS(projectName):
    """package pe.edu.upc.aaw.demo1_202302_si63.util;

    import java.io.IOException;

    import javax.servlet.Filter;
    import javax.servlet.FilterChain;
    import javax.servlet.FilterConfig;
    import javax.servlet.ServletException;
    import javax.servlet.ServletRequest;
    import javax.servlet.ServletResponse;
    import javax.servlet.http.HttpServletRequest;
    import javax.servlet.http.HttpServletResponse;

    import org.springframework.core.Ordered;
    import org.springframework.core.annotation.Order;
    import org.springframework.stereotype.Component;

    @Component
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public class CORS implements Filter {

        @Override
        public void init(FilterConfig filterConfig) throws ServletException {
            // TODO Auto-generated method stub

        }

        @Override
        public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
                throws IOException, ServletException {
            HttpServletResponse response = (HttpServletResponse) res;
            HttpServletRequest request = (HttpServletRequest) req;

            response.setHeader("Access-Control-Allow-Origin", "*");
            response.setHeader("Access-Control-Allow-Methods", "DELETE, GET, OPTIONS, PATCH, POST, PUT");
            response.setHeader("Access-Control-Max-Age", "3600");
            response.setHeader("Access-Control-Allow-Headers",
                    "x-requested-with, authorization, Content-Type, Authorization, credential, X-XSRF-TOKEN");

            if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
                response.setStatus(HttpServletResponse.SC_OK);
            } else {
                chain.doFilter(req, res);
            }
            // chain.doFilter(req, res);
        }

        @Override
        public void destroy() {
            // TODO Auto-generated method stub
        }
    }"""
    content = ''
    # Generate package
    content += f'package pe.edu.upc.aaw.{projectName}.util;\n\n'
    # Generate imports
    content += 'import java.io.IOException;\n'
    content += 'import javax.servlet.Filter;\n'
    
    content += 'import javax.servlet.FilterChain;\n'
    content += 'import javax.servlet.FilterConfig;\n'
    content += 'import javax.servlet.ServletException;\n'
    content += 'import javax.servlet.ServletRequest;\n'
    content += 'import javax.servlet.ServletResponse;\n'
    content += 'import javax.servlet.http.HttpServletRequest;\n'
    content += 'import javax.servlet.http.HttpServletResponse;\n'
    content += 'import org.springframework.core.Ordered;\n'
    content += 'import org.springframework.core.annotation.Order;\n'
    content += 'import org.springframework.stereotype.Component;\n\n'

    content += '@Component\n'
    content += '@Order(Ordered.HIGHEST_PRECEDENCE)\n'
    content += 'public class CORS implements Filter {\n\n'

    content += '@Override\n'
    content += 'public void init(FilterConfig filterConfig) throws ServletException {\n'
    content += '    // TODO Auto-generated method stub\n\n'
    content += '}\n\n'
    
    content += '@Override\n'
    content += 'public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)\n'
    content += '        throws IOException, ServletException {\n'
    content += '    HttpServletResponse response = (HttpServletResponse) res;\n'
    content += '    HttpServletRequest request = (HttpServletRequest) req;\n\n'
    
    content += '    response.setHeader("Access-Control-Allow-Origin", "*");\n'
    content += '    response.setHeader("Access-Control-Allow-Methods", "DELETE, GET, OPTIONS, PATCH, POST, PUT");\n'
    content += '    response.setHeader("Access-Control-Max-Age", "3600");\n'
    content += '    response.setHeader("Access-Control-Allow-Headers",\n'
    content += '            "x-requested-with, authorization, Content-Type, Authorization, credential, X-XSRF-TOKEN");\n\n'

    content += '    if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {\n'
    content += '        response.setStatus(HttpServletResponse.SC_OK);\n'
    content += '    } else {\n'
    content += '        chain.doFilter(req, res);\n'
    content += '    }\n'
    content += '    // chain.doFilter(req, res);\n'
    content += '}\n\n'

    content += '@Override\n'
    content += 'public void destroy() {\n'
    content += '    // TODO Auto-generated method stub\n'
    content += '}\n'
    content += '}'

    # Create a folder called ProjectName/util
    if not os.path.exists(f'testenv/{projectName}/util'):
        os.makedirs(f'testenv/{projectName}/util')

    # Create a txt file, write the data and close it. In a folder called ProjectName/util
    f = open(f'testenv/{projectName}/util/CORS.java', 'w')
    f.write(content)
    f.close()

# security
# generate JwtAuthenticationEntryPoint
def generateJwtAuthenticationEntryPoint(projectName):
    content = f"""
    package pe.edu.upc.aaw.{projectName}.security;

    import java.io.IOException;
    import java.io.Serializable;

    import javax.servlet.http.HttpServletRequest;
    import javax.servlet.http.HttpServletResponse;

    import org.springframework.security.core.AuthenticationException;
    import org.springframework.security.web.AuthenticationEntryPoint;
    import org.springframework.stereotype.Component;

    //Clase 7
    @Component
    public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint, Serializable {{

        private static final long serialVersionUID = -7858869558953243875L;

        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response,
                            AuthenticationException authException) throws IOException {{

            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
        }}
    }}
    """

    # Create a folder called ProjectName/security
    if not os.path.exists(f'testenv/{projectName}/security'):
        os.makedirs(f'testenv/{projectName}/security')

    # Create a txt file, write the data and close it. In a folder called ProjectName/security
    f = open(f'testenv/{projectName}/security/JwtAuthenticationEntryPoint.java', 'w')
    f.write(content)
    f.close()

# generate JwtUserDetailsService
def JwtRequest(projectName):
    content = f"""
    package pe.edu.upc.aaw.{projectName}.security;

    import java.io.Serializable;

    public class JwtRequest implements Serializable {{
        private static final long serialVersionUID = 5926468583005150707L;
        private String username;
        private String password;
        public JwtRequest() {{
            super();
            // TODO Auto-generated constructor stub
        }}
        public JwtRequest(String username, String password) {{
            super();
            this.username = username;
            this.password = password;
        }}
        public static long getSerialversionuid() {{
            return serialVersionUID;
        }}
        public String getUsername() {{
            return username;
        }}
        public String getPassword() {{
            return password;
        }}
        public void setUsername(String username) {{
            this.username = username;
        }}
        public void setPassword(String password) {{
            this.password = password;
        }}
    }}
    """

    # Create a folder called ProjectName/security
    if not os.path.exists(f'testenv/{projectName}/security'):
        os.makedirs(f'testenv/{projectName}/security')

    # Create a txt file, write the data and close it. In a folder called ProjectName/security
    f = open(f'testenv/{projectName}/security/JwtRequest.java', 'w')
    f.write(content)
    f.close()

# generate JwtUserDetailsService
def JwtRequestFilter(projectName):
    content=f"""
    package pe.edu.upc.aaw.{projectName}.security;

    import io.jsonwebtoken.ExpiredJwtException;
    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
    import org.springframework.security.core.context.SecurityContextHolder;
    import org.springframework.security.core.userdetails.UserDetails;
    import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
    import org.springframework.stereotype.Component;
    import org.springframework.web.filter.OncePerRequestFilter;
    import pe.edu.upc.aaw.{projectName}.serviceimplements.JwtUserDetailsService;

    import javax.servlet.FilterChain;
    import javax.servlet.ServletException;
    import javax.servlet.http.HttpServletRequest;
    import javax.servlet.http.HttpServletResponse;
    import java.io.IOException;

    //Clase 6
    @Component
    public class JwtRequestFilter extends OncePerRequestFilter {{
        @Autowired
        private JwtUserDetailsService jwtUserDetailsService;
        @Autowired
        private JwtTokenUtil jwtTokenUtil;
        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {{
            final String requestTokenHeader = request.getHeader("Authorization");
            String username = null;
            String jwtToken = null;
            // JWT Token is in the form "Bearer token". Remove Bearer word and get
            // only the Token
            if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {{
                jwtToken = requestTokenHeader.substring(7);
                try {{
                    username = jwtTokenUtil.getUsernameFromToken(jwtToken);
                }} catch (IllegalArgumentException e) {{
                    System.out.println("No se puede encontrar el token JWT");
                }} catch (ExpiredJwtException e) {{
                    System.out.println("Token JWT ha expirado");
                }}
            }} else {{
                logger.warn("JWT Token no inicia con la palabra Bearer");
            }}

            // Once we get the token validate it.
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {{

                UserDetails userDetails = this.jwtUserDetailsService.loadUserByUsername(username);

                // if token is valid configure Spring Security to manually set
                // authentication
                if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {{

                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    usernamePasswordAuthenticationToken
                            .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    // After setting the Authentication in the context, we specify
                    // that the current user is authenticated. So it passes the
                    // Spring Security Configurations successfully.
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                }}
            }}
            chain.doFilter(request, response);
        }}
    }}
    """

    # Create a folder called ProjectName/security
    if not os.path.exists(f'testenv/{projectName}/security'):
        os.makedirs(f'testenv/{projectName}/security')

    # Create a txt file, write the data and close it. In a folder called ProjectName/security
    f = open(f'testenv/{projectName}/security/JwtRequestFilter.java', 'w')
    f.write(content)
    f.close()

# generate JwtResponse
def JwtResponse(projectName):
    content = f"""
    package pe.edu.upc.aaw.{projectName}.security;
    import java.io.Serializable;

    public class JwtResponse implements Serializable {{

        private static final long serialVersionUID = -8091879091924046844L;
        private final String jwttoken;

        public String getJwttoken() {{
            return jwttoken;
        }}

        public JwtResponse(String jwttoken) {{
            super();
            this.jwttoken = jwttoken;
        }}
    }}
    """

    # Create a folder called ProjectName/security
    if not os.path.exists(f'testenv/{projectName}/security'):
        os.makedirs(f'testenv/{projectName}/security')

    # Create a txt file, write the data and close it. In a folder called ProjectName/security
    f = open(f'testenv/{projectName}/security/JwtResponse.java', 'w')
    f.write(content)
    f.close()

# generate JwtTokenUtil
def JwtTokenUtil(projectName):
    content = f"""
    package pe.edu.upc.aaw.{projectName}.security;
    import java.io.Serializable;
    import java.util.Date;
    import java.util.HashMap;
    import java.util.Map;
    import java.util.function.Function;
    import java.util.stream.Collectors;

    import org.springframework.beans.factory.annotation.Value;
    import org.springframework.security.core.userdetails.UserDetails;
    import org.springframework.stereotype.Component;

    import io.jsonwebtoken.Claims;
    import io.jsonwebtoken.Jwts;
    import io.jsonwebtoken.SignatureAlgorithm;

    //Clase 1
    @Component
    public class JwtTokenUtil implements Serializable {{

        private static final long serialVersionUID = -2550185165626007488L;

        //milisegundos || 18 minutos, le quitamos mil 18 segundos demo
        public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60 * 1000;

        @Value("${{jwt.secret}}")
        private String secret;

        //retrieve username from jwt token
        public String getUsernameFromToken(String token) {{
            return getClaimFromToken(token, Claims::getSubject);
        }}

        //retrieve expiration date from jwt token
        public Date getExpirationDateFromToken(String token) {{
            return getClaimFromToken(token, Claims::getExpiration);
        }}

        public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {{
            final Claims claims = getAllClaimsFromToken(token);
            return claimsResolver.apply(claims);
        }}
        //for retrieveing any information from token we will need the secret key
        private Claims getAllClaimsFromToken(String token) {{
            return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
        }}

        //check if the token has expired
        private Boolean isTokenExpired(String token) {{
            final Date expiration = getExpirationDateFromToken(token);
            return expiration.before(new Date());
        }}

        //generate token for user
        public String generateToken(UserDetails userDetails) {{
            Map<String, Object> claims = new HashMap<>();
            claims.put("username", userDetails.getUsername());
            claims.put("role",userDetails.getAuthorities().stream().map(r->r.getAuthority()).collect(Collectors.joining()));
            return doGenerateToken(claims, userDetails.getUsername());
        }}

        //while creating the token -
        //1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID
        //2. Sign the JWT using the HS512 algorithm and secret key.
        //3. According to JWS Compact Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
        //   compaction of the JWT to a URL-safe string
        private String doGenerateToken(Map<String, Object> claims, String subject) {{

            return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY))
                    .signWith(SignatureAlgorithm.HS512, secret).compact();
        }}

        //validate token
        public Boolean validateToken(String token, UserDetails userDetails) {{
            final String username = getUsernameFromToken(token);
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        }}
    }}
    """

    # Create a folder called ProjectName/security
    if not os.path.exists(f'testenv/{projectName}/security'):
        os.makedirs(f'testenv/{projectName}/security')

    # Create a txt file, write the data and close it. In a folder called ProjectName/security
    f = open(f'testenv/{projectName}/security/JwtTokenUtil.java', 'w')
    f.write(content)
    f.close()

# WebSecurityConfig
def WebSecurityConfig(projectName):
    content = f"""
    package pe.edu.upc.aaw.{projectName}.security;
    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.beans.factory.annotation.Qualifier;
    import org.springframework.context.annotation.Bean;
    import org.springframework.context.annotation.Configuration;
    import org.springframework.http.HttpMethod;
    import org.springframework.security.authentication.AuthenticationManager;
    import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
    import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
    import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
    import org.springframework.security.config.annotation.web.builders.HttpSecurity;
    import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
    import org.springframework.security.config.http.SessionCreationPolicy;
    import org.springframework.security.core.userdetails.UserDetailsService;
    import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
    import org.springframework.security.crypto.password.PasswordEncoder;
    import org.springframework.security.web.SecurityFilterChain;
    import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
    import org.springframework.web.servlet.HandlerExceptionResolver;

    //@Profile(value = {{"development", "production"}})
    //Clase S7
    @Configuration
    @EnableWebSecurity
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    public class WebSecurityConfig {{

        @Autowired
        private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

        @Autowired
        private UserDetailsService jwtUserDetailsService;

        @Autowired
        private JwtRequestFilter jwtRequestFilter;

        @Autowired
        @Qualifier("handlerExceptionResolver")
        private HandlerExceptionResolver exceptionResolver;

        @Bean
        public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {{
            return authenticationConfiguration.getAuthenticationManager();
        }}

        @Bean
        public static PasswordEncoder passwordEncoder() {{
            return new BCryptPasswordEncoder();
        }}

        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {{
            auth.userDetailsService(jwtUserDetailsService).passwordEncoder(passwordEncoder());
        }}

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {{
            httpSecurity
                    .csrf().disable()
                    .authorizeRequests()
                    .antMatchers("/authenticate").permitAll()
                    .antMatchers(HttpMethod.POST, "/users").permitAll()
                    .antMatchers(HttpMethod.GET, "/users/buscar/{{username}}").permitAll()
                    .anyRequest().authenticated()
                    .and()
                    .exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint)
                    .and()
                    .formLogin().disable()
                    .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

            httpSecurity.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

            return httpSecurity.build();
        }}
    }}
    """

    # Create a folder called ProjectName/security
    if not os.path.exists(f'testenv/{projectName}/security'):
        os.makedirs(f'testenv/{projectName}/security')

    # Create a txt file, write the data and close it. In a folder called ProjectName/security
    f = open(f'testenv/{projectName}/security/WebSecurityConfig.java', 'w')
    f.write(content)
    f.close()

# generate JwtUserDetailsService
def JwtUserDetailsService(projectName):
    content = f"""
    package pe.edu.upc.aaw.{projectName}.serviceimplements;
    import java.util.ArrayList;
    import java.util.List;
    import org.springframework.beans.factory.annotation.Autowired;

    import org.springframework.security.core.GrantedAuthority;
    import org.springframework.security.core.authority.SimpleGrantedAuthority;
    import org.springframework.security.core.userdetails.UserDetails;
    import org.springframework.security.core.userdetails.UserDetailsService;
    import org.springframework.security.core.userdetails.UsernameNotFoundException;
    import org.springframework.stereotype.Service;
    import pe.edu.upc.aaw.{projectName}.entities.Users;
    import pe.edu.upc.aaw.{projectName}.repositories.IUserRepository;

    @Service
    public class JwtUserDetailsService implements UserDetailsService{{
        @Autowired
        private IUserRepository repo;

        /*@Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {{
            //Aqui lógica para buscar el usuario en BD
            //Usuario defecto web:password

            if ("web".equals(username)) {{
                return new User("web", "$2a$12$CTtjF8P3IJVK6pP4w9pTxuldMqQRrfrLbLLIlasdu2K6ii2vWGly2",
                        new ArrayList<>());
            }} else {{
                throw new UsernameNotFoundException("Usuario no encontrado: " + username);
            }}
        }}*/
        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {{
            Users user = repo.findByUsername(username);

            if(user == null) {{
                throw new UsernameNotFoundException(String.format("User not exists", username));
            }}

            List<GrantedAuthority> roles = new ArrayList<>();

            user.getRoles().forEach(rol -> {{
                roles.add(new SimpleGrantedAuthority(rol.getRol()));
            }});

            UserDetails ud = new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), user.getEnabled(), true, true, true, roles);

            return ud;
        }}
    }}
    """

    # Create a folder called ProjectName/serviceimplements
    if not os.path.exists(f'testenv/{projectName}/serviceimplements'):
        os.makedirs(f'testenv/{projectName}/serviceimplements')

    # Create a txt file, write the data and close it. In a folder called ProjectName/serviceimplements
    f = open(f'testenv/{projectName}/serviceimplements/JwtUserDetailsService.java', 'w')
    f.write(content)
    f.close()

# generate user entity
def generateUserEntity(projectName):
    content = f"""
    package pe.edu.upc.aaw.{projectName}.entities;
    import com.fasterxml.jackson.annotation.JsonManagedReference;
    import java.io.Serializable;
    import java.util.List;
    import javax.persistence.*;
    import pe.edu.upc.aaw.{projectName}.entities.Role;

    @Entity
    @Table(name = "Users")
    public class Users implements Serializable {{

        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        @Column(length = 30, unique = true)
        private String username;
        @Column(length = 200)
        private String password;
        private Boolean enabled;

        @JsonManagedReference
        @OneToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
        @JoinColumn(name = "user_id")
        private List<Role> roles;

        public Long getId() {{
            return id;
        }}

        public void setId(Long id) {{
            this.id = id;
        }}

        public String getUsername() {{
            return username;
        }}

        public void setUsername(String username) {{
            this.username = username;
        }}

        public String getPassword() {{
            return password;
        }}

        public void setPassword(String password) {{
            this.password = password;
        }}

        public Boolean getEnabled() {{
            return enabled;
        }}

        public void setEnabled(Boolean enabled) {{
            this.enabled = enabled;
        }}

        public List<Role> getRoles() {{
            return roles;
        }}

        public void setRoles(List<Role> roles) {{
            this.roles = roles;
        }}

    }}
    """

    # Create a folder called ProjectName/entities
    if not os.path.exists(f'testenv/{projectName}/entities'):
        os.makedirs(f'testenv/{projectName}/entities')

    # Create a txt file, write the data and close it. In a folder called ProjectName/entities
    f = open(f'testenv/{projectName}/entities/Users.java', 'w')
    f.write(content)
    f.close()

# generate role entity
def generateRoleEntity(projectName):
    content = f"""
    package pe.edu.upc.aaw.{projectName}.entities;

    import com.fasterxml.jackson.annotation.JsonBackReference;

    import java.io.Serializable;
    import javax.persistence.*;


    @Entity
    @Table(name = "Roles", uniqueConstraints = {{@UniqueConstraint(columnNames = {{"user_id", "rol"}})}})
    public class Role implements Serializable {{

        private static final long serialVersionUID = 1L;

        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        private String rol;

        @JsonBackReference
        @ManyToOne
        @JoinColumn(name = "user_id", nullable = false)
        private Users user;

        public Users getUser() {{
            return user;
        }}

        public void setUser(Users user) {{
            this.user = user;
        }}

        public Long getId() {{
            return id;
        }}

        public void setId(Long id) {{
            this.id = id;
        }}

        public String getRol() {{
            return rol;
        }}

        public void setRol(String rol) {{
            this.rol = rol;
        }}
    }}
    """

    # Create a folder called ProjectName/entities
    if not os.path.exists(f'testenv/{projectName}/entities'):
        os.makedirs(f'testenv/{projectName}/entities')

    # Create a txt file, write the data and close it. In a folder called ProjectName/entities
    f = open(f'testenv/{projectName}/entities/Role.java', 'w')
    f.write(content)
    f.close()

# generate user repository
def generateUserRepository(projectName):
    content=f"""
    package pe.edu.upc.aaw.{projectName}.repositories;

    import org.springframework.data.jpa.repository.JpaRepository;
    import org.springframework.data.jpa.repository.Modifying;
    import org.springframework.data.jpa.repository.Query;
    import org.springframework.data.repository.query.Param;
    import org.springframework.transaction.annotation.Transactional;
    import pe.edu.upc.aaw.{projectName}.entities.Users;

    public interface IUserRepository extends JpaRepository<Users, Long>{{
        public Users findByUsername(String username);

        //BUSCAR POR NOMBRE
        @Query("select count(u.username) from Users u where u.username =:username")
        public int buscarUsername(@Param("username") String nombre);

        //ELIMINAR ROL POR ID
        @Modifying
        @Query("DELETE FROM Role r WHERE r.user.id = :userId")
        void deleteRolesByUserId(@Param("userId") Long userId);

        //ELIMINAR USUARIO POR ID
        @Modifying
        @Query("DELETE FROM Users u WHERE u.id = :userId")
        void deleteById(@Param("userId") Long userId);

        //INSERTAR ROLES
        @Transactional
        @Modifying
        @Query(value = "insert into roles (rol, user_id) VALUES (:rol, :user_id)", nativeQuery = true)
        public void insRol(@Param("rol") String authority, @Param("user_id") Long user_id);
    }}
    """

    # Create a folder called ProjectName/repositories
    if not os.path.exists(f'testenv/{projectName}/repositories'):
        os.makedirs(f'testenv/{projectName}/repositories')

    # Create a txt file, write the data and close it. In a folder called ProjectName/repositories
    f = open(f'testenv/{projectName}/repositories/IUserRepository.java', 'w')
    f.write(content)
    f.close()

# generate user service interface
def generateUserServiceInterface(projectName):
    content = f"""
    package pe.edu.upc.aaw.{projectName}.serviceinterfaces;

    import pe.edu.upc.aaw.{projectName}.entities.Users;
    import java.util.List;

    public interface IUsersService {{
        void insert(Users Users);
        void delete(Long id);
        Users listId(Long id);
        List<Users> list();
        void insertAndAssignRole(Users user, String roleName);
        Users findByUsername(String username);
    }}
    """

    # Create a folder called ProjectName/serviceinterfaces
    if not os.path.exists(f'testenv/{projectName}/serviceinterfaces'):
        os.makedirs(f'testenv/{projectName}/serviceinterfaces')

    # Create a txt file, write the data and close it. In a folder called ProjectName/serviceinterfaces
    f = open(f'testenv/{projectName}/serviceinterfaces/IUsersService.java', 'w')
    f.write(content)
    f.close()

# generate user service implement
    content = f"""
    package pe.edu.upc.aaw.{projectName}.serviceimplements;

    import org.springframework.beans.factory.annotation.*;
    import org.springframework.stereotype.*;
    import org.springframework.transaction.annotation.Transactional;
    import pe.edu.upc.aaw.{projectName}.entities.Users;
    import pe.edu.upc.aaw.{projectName}.repositories.IUserRepository;
    import pe.edu.upc.aaw.{projectName}.serviceinterfaces.IUsersService;

    import java.util.List;

    @Service
    public class UsersServiceImplement implements IUsersService {{
        @Autowired
        private IUserRepository myRepository;

        // Add an item to table
        @Override
        public void insert(Users Users) {{
            myRepository.save(Users);
        }}
        @Override
        @Transactional
        public void insertAndAssignRole(Users user, String roleName) {{
            // Guardar el usuario y obtener el ID generado
            Long userId = myRepository.save(user).getId();
            // Asignar el rol al usuario
            myRepository.insRol(roleName, userId);
        }}

        // Delete an item by ID on table
        @Override
        @Transactional
        public void delete(Long idUsers) {{
            myRepository.deleteRolesByUserId(idUsers);
            myRepository.deleteById(idUsers);
        }}

        // Retrieve an items by ID from table
        @Override
        public Users listId(Long idUsers){{
            return myRepository.findById(idUsers).orElse(new Users());
        }}

        // Retrieve all items from table
        @Override
        public List<Users> list() {{
            return myRepository.findAll();
        }}

        @Override
        public Users findByUsername(String username) {{
            return myRepository.findByUsername(username);
        }}
    }}
    """

    # Create a folder called ProjectName/serviceimplements
    if not os.path.exists(f'testenv/{projectName}/serviceimplements'):
        os.makedirs(f'testenv/{projectName}/serviceimplements')

    # Create a txt file, write the data and close it. In a folder called ProjectName/serviceimplements
    f = open(f'testenv/{projectName}/serviceimplements/UsersServiceImplement.java', 'w')
    f.write(content)
    f.close()

# generate user service implement
def generateUserServiceImplement(projectName):
    content=f"""
    package pe.edu.upc.aaw.{projectName}.serviceimplements;

    import org.springframework.beans.factory.annotation.*;
    import org.springframework.stereotype.*;
    import org.springframework.transaction.annotation.Transactional;
    import pe.edu.upc.aaw.{projectName}.entities.Users;
    import pe.edu.upc.aaw.{projectName}.repositories.IUserRepository;
    import pe.edu.upc.aaw.{projectName}.serviceinterfaces.IUsersService;

    import java.util.List;

    @Service
    public class UsersServiceImplement implements IUsersService {{
        @Autowired
        private IUserRepository myRepository;

        // Add an item to table
        @Override
        public void insert(Users Users) {{
            myRepository.save(Users);
        }}
        @Override
        @Transactional
        public void insertAndAssignRole(Users user, String roleName) {{
            // Guardar el usuario y obtener el ID generado
            Long userId = myRepository.save(user).getId();
            // Asignar el rol al usuario
            myRepository.insRol(roleName, userId);
        }}

        // Delete an item by ID on table
        @Override
        @Transactional
        public void delete(Long idUsers) {{
            myRepository.deleteRolesByUserId(idUsers);
            myRepository.deleteById(idUsers);
        }}

        // Retrieve an items by ID from table
        @Override
        public Users listId(Long idUsers){{
            return myRepository.findById(idUsers).orElse(new Users());
        }}

        // Retrieve all items from table
        @Override
        public List<Users> list() {{
            return myRepository.findAll();
        }}

        @Override
        public Users findByUsername(String username) {{
            return myRepository.findByUsername(username);
        }}
    }}
    """

    # Create a folder called ProjectName/serviceimplements
    if not os.path.exists(f'testenv/{projectName}/serviceimplements'):
        os.makedirs(f'testenv/{projectName}/serviceimplements')

    # Create a txt file, write the data and close it. In a folder called ProjectName/serviceimplements
    f = open(f'testenv/{projectName}/serviceimplements/UsersServiceImplement.java', 'w')
    f.write(content)
    f.close()

# Generate the user dto
def generateUserDTO(projectName):
    content = f"""
    package pe.edu.upc.aaw.{projectName}.dtos;

    import pe.edu.upc.aaw.{projectName}.entities.*;
    import java.time.LocalDate;

    public class UsersDTO {{
        private Long id;
        private String username;
        private String password;
        private boolean enabled;

        public Long getId() {{
            return id;
        }}

        public void setId(Long id) {{
            this.id = id;
        }}

        public String getUsername() {{
            return username;
        }}

        public void setUsername(String username) {{
            this.username = username;
        }}

        public String getPassword() {{
            return password;
        }}

        public void setPassword(String password) {{
            this.password = password;
        }}

        public boolean isEnabled() {{
            return enabled;
        }}

        public void setEnabled(boolean enabled) {{
            this.enabled = enabled;
        }}
    }}
    """

    # Create a folder called ProjectName/dtos
    if not os.path.exists(f'testenv/{projectName}/dtos'):
        os.makedirs(f'testenv/{projectName}/dtos')

    # Create a txt file, write the data and close it. In a folder called ProjectName/dtos
    f = open(f'testenv/{projectName}/dtos/UsersDTO.java', 'w')
    f.write(content)
    f.close()

# Generate jwt authentication controller
def generateJwtAuthenticationController(projectName):
    content=f"""
    package pe.edu.upc.aaw.{projectName}.controllers;

    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.http.ResponseEntity;
    import org.springframework.security.authentication.AuthenticationManager;
    import org.springframework.security.authentication.BadCredentialsException;
    import org.springframework.security.authentication.DisabledException;
    import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
    import org.springframework.security.core.userdetails.UserDetails;
    import org.springframework.web.bind.annotation.CrossOrigin;
    import org.springframework.web.bind.annotation.PostMapping;
    import org.springframework.web.bind.annotation.RequestBody;
    import org.springframework.web.bind.annotation.RestController;
    import pe.edu.upc.aaw.{projectName}.security.JwtRequest;
    import pe.edu.upc.aaw.{projectName}.security.JwtResponse;
    import pe.edu.upc.aaw.{projectName}.security.JwtTokenUtil;
    import pe.edu.upc.aaw.{projectName}.serviceimplements.JwtUserDetailsService;

    @RestController
    @CrossOrigin
    public class JwtAuthenticationController {{
        @Autowired
        private AuthenticationManager authenticationManager;
        @Autowired
        private JwtTokenUtil jwtTokenUtil;
        @Autowired
        private JwtUserDetailsService userDetailsService;
        @PostMapping("/authenticate")
        public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtRequest authenticationRequest) throws Exception {{
            authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());
            final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
            final String token = jwtTokenUtil.generateToken(userDetails);
            return ResponseEntity.ok(new JwtResponse(token));
        }}
        private void authenticate(String username, String password) throws Exception {{
            try {{
                authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
            }} catch (DisabledException e) {{
                throw new Exception("USER_DISABLED", e);
            }} catch (BadCredentialsException e) {{
                throw new Exception("INVALID_CREDENTIALS", e);
            }}
        }}
    }}
    """

    # Create a folder called ProjectName/controllers
    if not os.path.exists(f'testenv/{projectName}/controllers'):
        os.makedirs(f'testenv/{projectName}/controllers')

    # Create a txt file, write the data and close it. In a folder called ProjectName/controllers
    f = open(f'testenv/{projectName}/controllers/JwtAuthenticationController.java', 'w')
    f.write(content)
    f.close()

# Generate the user controller
def generateUserController(projectName):
    content=f"""
    package pe.edu.upc.aaw.{projectName}.controllers;

    import org.modelmapper.ModelMapper;
    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.web.bind.annotation.*;
    import pe.edu.upc.aaw.{projectName}.dtos.UsersDTO;
    import pe.edu.upc.aaw.{projectName}.entities.Users;
    import pe.edu.upc.aaw.{projectName}.security.WebSecurityConfig;
    import pe.edu.upc.aaw.{projectName}.serviceinterfaces.IUsersService;

    import java.util.List;
    import java.util.stream.Collectors;

    @RestController
    @CrossOrigin(origins = "http://localhost:4200")
    @RequestMapping("/users")
    public class UsersController {{
        @Autowired
        private IUsersService myService;

        // Add an item to table
        @PostMapping
        public void registrar(@RequestBody UsersDTO dto) {{
            ModelMapper m = new ModelMapper();
            Users myItem = m.map(dto, Users.class);
            // Encriptar la contraseña del usuario antes de guardarla
            myItem.setPassword(WebSecurityConfig.passwordEncoder().encode(myItem.getPassword()));
            myService.insertAndAssignRole(myItem, "ESTUDIANTE");
        }}

        // Delete an item by ID on table
        @DeleteMapping("/{{id}}")
        public void eliminar(@PathVariable("id")Long id){{
            myService.delete(id);
        }}

        // Retrieve an items by ID from table
        @GetMapping("/{{id}}")
        public UsersDTO listarId(@PathVariable("id")Long id){{
            ModelMapper m = new ModelMapper();
            UsersDTO myItem = m.map(myService.listId(id), UsersDTO.class);
            return myItem;
        }}

        // Retrieve all items from table
        @GetMapping
        public List<UsersDTO> listar(){{
            return myService.list().stream().map(x -> {{
                ModelMapper m = new ModelMapper();
                return m.map(x, UsersDTO.class);
            }}).collect(Collectors.toList());
        }}

        // (Exclusive to controller) Modify values on table
        @PutMapping
        public void modificar(@RequestBody UsersDTO dto) {{
            ModelMapper m = new ModelMapper();
            Users d = m.map(dto, Users.class);
            // Encriptar la contraseña del usuario antes de modificarla
            d.setPassword(WebSecurityConfig.passwordEncoder().encode(d.getPassword()));
            myService.insert(d);
        }}
        @GetMapping("/buscar/{{username}}")
        public UsersDTO buscarPorUsername(@PathVariable("username") String username) {{
            Users user = myService.findByUsername(username);
            if (user != null) {{
                ModelMapper m = new ModelMapper();
                return m.map(user, UsersDTO.class);
            }} else {{
                // Manejar el caso en el que el usuario no existe
                return null;
            }}
        }}
    }}
    """

    # Create a folder called ProjectName/controllers
    if not os.path.exists(f'testenv/{projectName}/controllers'):
        os.makedirs(f'testenv/{projectName}/controllers')

    # Create a txt file, write the data and close it. In a folder called ProjectName/controllers
    f = open(f'testenv/{projectName}/controllers/UsersController.java', 'w')
    f.write(content)
    f.close()

# Generates all files for each entity
def generateAllFiles(projectName, entities):
    # Generate all files for each entityAlternativa
    for entity in entities:
        generateEntityFile(projectName, entity['entityName'], entity['attributes'])
        generateRepositoryFile(projectName, entity['entityName'])
        generateServiceInterface(projectName, entity['entityName'])
        generateServiceImplement(projectName, entity['entityName'])
        generateDTO(projectName, entity['entityName'], entity['attributes'])
        generateController(projectName, entity['entityName'])

    # Generate CORS util
    generateUtilForCORS(projectName)

    # Generate security
    if useSecurity:
        generateJwtAuthenticationEntryPoint(projectName)
        JwtRequest(projectName)
        JwtRequestFilter(projectName)
        JwtResponse(projectName)
        JwtTokenUtil(projectName)
        WebSecurityConfig(projectName)
        JwtUserDetailsService(projectName)
        generateUserEntity(projectName)
        generateRoleEntity(projectName)
        generateUserRepository(projectName)
        generateUserServiceInterface(projectName)
        generateUserController(projectName)
        generateUserDTO(projectName)
        generateUserServiceImplement(projectName)
        generateJwtAuthenticationController(projectName)

# +++++++++++++++++
# +++++ MAIN ++++++
generateAllFiles(projectName, entities)