<?php
// Function to create a sql connection.
function getDB() {
  $dbhost="10.9.0.6";
  $dbuser="seed";
  $dbpass="dees";
  $dbname="sqllab_users";

  // Create a DB connection
  $conn = new mysqli($dbhost, $dbuser, $dbpass, $dbname);
  if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error . "\n");
  }
  return $conn;
}

$input_uname = $_GET['username'];
$input_pwd = $_GET['Password'];
$hashed_pwd = sha1($input_pwd);

// create a connection
$conn = getDB();

// Query template
$sql = "SELECT id, name, eid, salary, ssn
        FROM credential
        WHERE name= ? and Password= ?" ;
        
//Send code        
$stmt = $conn->prepare($sql);

//Send data
$stmt->bind_param("ss", $input_uname, $hashed_pwd);

//start execution
$stmt->execute();
//get results
$result = $stmt->get_result();
           
if ($result->num_rows > 0) {
  // only take the first row 
  $firstrow = $result->fetch_assoc();
  $id     = $firstrow["id"];
  $name   = $firstrow["name"];
  $eid    = $firstrow["eid"];
  $salary = $firstrow["salary"];
  $ssn    = $firstrow["ssn"];
}

// close the sql connection
$stmt->close();
$conn->close();
?>