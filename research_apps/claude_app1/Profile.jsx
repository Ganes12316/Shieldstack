function Profile({ location }) {
  const bio = new URLSearchParams(location.search).get("bio") || "";
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}
export default Profile;