using Microsoft.AspNetCore.Mvc; 
using StudentApi.Models;
using StudentApi.DataSimulation;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Microsoft.Extensions.Logging;


namespace StudentApi.Controllers 
{

    [Authorize] //This means: Every endpoint inside this controller, Requires a valid JWT
    [ApiController] // Marks the class as a Web API controller with enhanced features.
    //  [Route("[controller]")] // Sets the route for this controller to "students", based on the controller name.
    [Route("api/Students")]

    public class StudentsController : ControllerBase // Declare the controller class inheriting from ControllerBase.
    {

        // we added this for logger...
        private readonly ILogger<StudentsController> _logger;

        public StudentsController(ILogger<StudentsController> logger)
        {
            _logger = logger;
        }



        [Authorize(Roles = "Admin")] //This will allow admin only to access the endpoint
        [HttpGet("All", Name ="GetAllStudents")] // Marks this method to respond to HTTP GET requests.
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]

        public ActionResult<IEnumerable<Student>> GetAllStudents() // Define a method to get all students.
        {
            //StudentDataSimulation.StudentsList.Clear();

            if (StudentDataSimulation.StudentsList.Count == 0) 
            {
                return NotFound("No Students Found!");
            }
            return Ok(StudentDataSimulation.StudentsList); // Returns the list of students.
        }



        [AllowAnonymous] //Because you have [Authorize] at controller level, these endpoints must override it with [AllowAnonymous]
        [HttpGet("Passed",Name = "GetPassedStudents")]

        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]

        // Method to get all students who passed
        public ActionResult<IEnumerable<Student>> GetPassedStudents()

        {
            var passedStudents = StudentDataSimulation.StudentsList.Where(student => student.Grade >= 50).ToList();
            //passedStudents.Clear();

            if (passedStudents.Count == 0)
            {
                return NotFound("No Students Passed");
            }


            return Ok(passedStudents); // Return the list of students who passed.
        }



        [AllowAnonymous] //Because you have [Authorize] at controller level, these endpoints must override it with [AllowAnonymous]
        [HttpGet("AverageGrade", Name = "GetAverageGrade")]

        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]

        public ActionResult<double> GetAverageGrade()
        {

         //   StudentDataSimulation.StudentsList.Clear();

            if (StudentDataSimulation.StudentsList.Count == 0)
            {
                return NotFound("No students found.");
            }

            var averageGrade = StudentDataSimulation.StudentsList.Average(student => student.Grade);
            return Ok(averageGrade);
        }




        // This endpoint retrieves a single student by ID.
        // It uses policy-based authorization to enforce ownership rules.
        [HttpGet("{id}", Name = "GetStudentById")]

        public async Task<ActionResult<Student>> GetStudentById(
            int id,

            // IAuthorizationService is injected directly into the action.
            // It allows the controller to ask the authorization system
            // whether the current user is allowed to access a specific resource.
            [FromServices] IAuthorizationService authorizationService)
        {
            // Validate the route parameter.
            // IDs less than 1 are considered invalid input.
            if (id < 1)
                return BadRequest("Invalid student id.");

            // Retrieve the student record being requested.
            // This represents the resource the user wants to access.
            var student = StudentDataSimulation.StudentsList
                .FirstOrDefault(s => s.Id == id);

            // If no student exists with this ID, return 404 Not Found.
            // This avoids exposing internal data or assumptions.
            if (student == null)
                return NotFound("Student not found.");

            // Ask the authorization system to evaluate the "StudentOwnerOrAdmin" policy.
            //
            // Parameters:
            // - User: the authenticated user (from the validated JWT)
            // - id: the resource being protected (student ID)
            // - "StudentOwnerOrAdmin": the policy name
            var authResult = await authorizationService.AuthorizeAsync(
                User,
                id,
                "StudentOwnerOrAdmin");

            // If the policy evaluation failed, the user is authenticated
            // but not authorized to access this resource.
            // This correctly returns HTTP 403 Forbidden.
            if (!authResult.Succeeded)
                return Forbid(); // 403 Forbidden

            // If all checks pass:
            // - The user is authenticated
            // - The student exists
            // - The user is either the owner or an admin
            // Access is granted and the student record is returned.
            return Ok(student);
        }






        //for add new we use Http Post
        [Authorize(Roles = "Admin")] //This will allow admin only to access the endpoint
        [HttpPost(Name = "AddStudent")]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]

        public ActionResult<Student> AddStudent(Student newStudent)
        {
            //we validate the data here
            if (newStudent == null || string.IsNullOrEmpty(newStudent.Name) || newStudent.Age < 0 || newStudent.Grade < 0)
            {
                return BadRequest("Invalid student data.");
            }

            newStudent.Id = StudentDataSimulation.StudentsList.Count > 0 ? StudentDataSimulation.StudentsList.Max(s => s.Id) + 1 : 1;
            StudentDataSimulation.StudentsList.Add(newStudent);
            
            //we dont return Ok here,we return createdAtRoute: this will be status code 201 created.
            return CreatedAtRoute("GetStudentById", new { id = newStudent.Id }, newStudent);

        }



        //here we use HttpDelete method

        // ✅ Admin-only endpoint: deleting a student is a privileged/destructive action
        // ✅ Therefore it MUST be audited (who did it, what happened, which target)
        [Authorize(Roles = "Admin")]
        [HttpDelete("{id}", Name = "DeleteStudent")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]

        public ActionResult DeleteStudent(int id)
        {
            // ✅ Capture IP once for tracing (helps investigations later)
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            // ✅ Identify the admin who is performing the action
            // ClaimTypes.NameIdentifier is what you put in JWT during login.
            var adminId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "unknown";

            // ===============================
            // Validation: invalid ID
            // ===============================
            if (id < 1)
            {
                // ✅ Audit attempt (invalid input) - still useful signal
                _logger.LogWarning(
                    "Admin action blocked (invalid id). AdminId={AdminId}, Action=DeleteStudent, TargetId={TargetId}, IP={IP}",
                    adminId,
                    id,
                    ip
                );

                return BadRequest($"Not accepted ID {id}");
            }

            // ===============================
            // Find student
            // ===============================
            var student = StudentDataSimulation.StudentsList.FirstOrDefault(s => s.Id == id);

            if (student == null)
            {
                // ✅ Audit: admin attempted to delete a non-existing student
                _logger.LogWarning(
                    "Admin action failed (target not found). AdminId={AdminId}, Action=DeleteStudent, TargetId={TargetId}, IP={IP}",
                    adminId,
                    id,
                    ip
                );

                return NotFound($"Student with ID {id} not found.");
            }

            // ===============================
            // Audit BEFORE deleting (recommended)
            // ===============================
            // ✅ Why before?
            // If delete throws or fails later, you still have the audit record of the attempt.
            _logger.LogInformation(
                "Admin action started. AdminId={AdminId}, Action=DeleteStudent, TargetId={TargetId}, TargetEmail={TargetEmail}, IP={IP}",
                adminId,
                student.Id,
                student.Email,
                ip
            );

            // Perform deletion
            StudentDataSimulation.StudentsList.Remove(student);

            // ===============================
            // Audit AFTER deleting (optional, confirms success)
            // ===============================
            _logger.LogInformation(
                "Admin action succeeded. AdminId={AdminId}, Action=DeleteStudent, TargetId={TargetId}, IP={IP}",
                adminId,
                id,
                ip
            );

            return Ok($"Student with ID {id} has been deleted.");
        }



        //here we use http put method for update
        [Authorize(Roles = "Admin")] //This will allow admin only to access the endpoint
        [HttpPut("{id}", Name = "UpdateStudent")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]

        public ActionResult<Student> UpdateStudent(int id, Student updatedStudent)
        {
            if (id < 1 || updatedStudent == null || string.IsNullOrEmpty(updatedStudent.Name) || updatedStudent.Age < 0 || updatedStudent.Grade < 0)
            {
                return BadRequest("Invalid student data.");
            }

            var student = StudentDataSimulation.StudentsList.FirstOrDefault(s => s.Id == id);
            if (student == null)
            {
                return NotFound($"Student with ID {id} not found.");
            }

            student.Name = updatedStudent.Name;
            student.Age = updatedStudent.Age;
            student.Grade = updatedStudent.Grade;

            return Ok(student);
        }


    }
}
