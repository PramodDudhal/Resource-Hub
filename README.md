# Academic Resource Hub

## Introduction
In the academic world, staying connected and sharing resources with classmates is crucial for success. This "Academic Resource Hub" is a central place where students can easily communicate and access all the materials they need. It ensures everyone knows what resources are available, benefiting not just individuals but the entire academic community. We beleive in the saying:
> Sharing is Caring 🖤

## Technologies Used
We have used the following technologies:

- <u>**Python-Flask:**</u> We have used python's framework: Flask as our backend. We chose to use it mainly because of the following features:
    1. <u>Lightweight and Flexible:</u> Flask is a micro-framework, meaning it's lightweight and offers flexibility in designing and structuring our backend according to our project's needs.

    2. <u>Easy to Learn:</u> Flask has a simple and intuitive syntax, making it relatively easy for us to learn and use.

    3. <u>Jinja2 Templating:</u> Flask integrates Jinja2 templating engine, which simplifies the process of creating dynamic web pages by allowing us to embed Python code directly into HTML templates.

    4. <u>Integration with Other Technologies:</u> Flask seamlessly integrates with other technologies and frameworks, such as SQLAlchemy for database integration.

- <u>**SQLAlchemy:**</u> We have used flask's integrated feature: SQLAlchemy to store our database. We chose to use it mainly because of the following features:
    1. <u>Flexible Querying:</u> SQLAlchemy provides a flexible query API that allowed us to construct complex database queries using Pythonic syntax.

    2. <u>Schema Definition and Migration:</u> SQLAlchemy allows us to define database schemas using Python classes and declarative syntax. It supports automatic schema generation based on class definitions and provides tools for database schema migration, making it easier to manage changes to the database schema over time.

    3. <u>Transaction Management:</u> SQLAlchemy simplifies transaction management by providing a unified interface for beginning, committing, and rolling back database transactions. This helps ensure data integrity and consistency in multi-step database operations.

- <u>**Bootstrap:**</u> We have used Bootstrap as it provides a collection of pre-designed HTML, CSS, and JavaScript components, templates, and utilities that streamline the process of building user interfaces. To be precise, we have used bootstrap version 4 in this project. We chose to use it mainly because of the following features:
    1. <u>Rapid Development:</u> Bootstrap allowed us to quickly prototype and build responsive web layouts using its ready-made components and grid system. This accelerated the development process and reduced the need for writing custom CSS from scratch.

    2. <u>Consistency and Customization:</u> Bootstrap promotes consistency in design by offering a unified set of styles, components, and typography. We could easily customize the appearance and behavior of Bootstrap components using CSS variables and custom themes to match our project's requirements.

    3. <u>Documentation and Resources:</u> Bootstrap offers comprehensive documentation, examples, and starter templates that guided us through the process of using its components and features effectively. This documentation includes code snippets, explanations, and usage guidelines, making it easier for us to learn and master Bootstrap.

## Features of our Project
The following features are provided by our project:

- **<u>Sign-in and Sign-out:</u>** Users using our website can seemlessly sign in and sign-out.

- **<u>User Authentication:</u>** User Authentication is implemented using Flask-Login extension.

- **<u>Forgot Password and Change Password:</u>** If users ever feel like changing passwords then they can change it. Also if users ever forget their password then they are mailed their original password with the help of OTP verification

- **<u>Discussion Forum:</u>** Users can use discussion forum and can communicate and ask doubts amongst themselves. They can post their doubts as well as comment on it.

- **<u>Viewing and Uploading Resources:</u>** This is the main crux of our whole project. Users can view and upload resources of all years and branches by selecting options within a form. All uploaded files are stored under the "uploads" folder

- **<u>Contact Us:</u>** By using this page, users can message us if they want.

- **<u>Miscellaneous Pages:</u>** Users can visit pages like FAQs, Testimonials, About Us, etc. to know more about our website

## Contributors
This project is contributed by Arnav Gavde and Pramod Dudhal. Both of us have created this project during the 4th semester of our 2nd year in COEP Technological University

## License
This project is licensed under the MIT License. See the [LICENSE](/LICENSE.md) file for details.