## Cisco IT HelpDesk

### Description
Cisco IT HelpDesk is a web-based application designed to facilitate the management of IT support tickets within an organization. It allows users to create, view, update, and delete support tickets, as well as provides administrators with tools for overseeing the support ticket system. The application is built using Flask, SQLAlchemy, and Flask-Login.

### Features
- User Authentication: Users can register and log in to access the IT HelpDesk system. Administrators have additional privileges compared to standard users.
- Ticket Management: Users can create new support tickets, view existing tickets, update ticket details, and delete their own tickets. Administrators have the ability to delete any ticket.
- Ticket Overview: The dashboard provides users with an overview of their support tickets, including the number of assigned, unassigned, resolved, and deleted tickets. It also displays the number of tickets created in the last week, month, and year.
- Sorting: Tickets are sorted based on the latest updated timestamp, with the most recent updates appearing at the top of the list.
- Admin Dashboard: Administrators have access to an admin dashboard where they can view and manage support tickets across all users. Deleted tickets are still visible to administrators and marked as "DELETED".
- User-Friendly Interface: The application features a clean and intuitive interface for easy navigation and interaction.

### Installation
To run Cisco IT HelpDesk locally, follow these steps:
1. Clone the repository to your local machine.
2. Install the required dependencies listed in the `requirements.txt` file using pip.
3. Set up a virtual environment for the project (optional but recommended).
4. Configure the database URI in the `config.py` file to point to your desired database.
5. Run the Flask application using the `flask run` command.

### Usage
1. Register for an account using the registration page.
2. Log in with your credentials to access the IT HelpDesk system.
3. Create new support tickets using the "Create Ticket" page.
4. View and update your existing tickets on the dashboard.
5. Administrators can access the admin dashboard to manage support tickets for all users.

### Contributing
Contributions to Cisco IT HelpDesk are welcome! To contribute:
1. Fork the repository and clone it to your local machine.
2. Create a new branch for your feature or bug fix.
3. Make your changes and ensure all tests pass.
4. Push your changes to your fork and submit a pull request to the main repository.

### License
This project is licensed under the [MIT License](LICENSE).

### Credits
- Developed by [Your Name]
- Inspired by [Related Project or Source]
- Built with Flask, SQLAlchemy, and Flask-Login.

### Contact
For questions or support, contact arsachde@cisco.com

### Version History
- v1.0 (25/03/2024): Initial release of Cisco IT HelpDesk.

### Acknowledgments
- Special thanks to [Acknowledged Individuals/Organizations] for their contributions and support.