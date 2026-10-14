import React from "react";

function Profile({ userBio }) {
  return (
    <div className="profile">
      <h3>About Me</h3>
      <div dangerouslySetInnerHTML={{ __html: userBio }} />
    </div>
  );
}

export default Profile;