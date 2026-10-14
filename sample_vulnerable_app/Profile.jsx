function Profile({ location }) {
  const bio = location.search;
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}