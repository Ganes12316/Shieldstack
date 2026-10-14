import DOMPurify from "dompurify";

function Profile({ location }) {
  const bio = DOMPurify.sanitize(location.search);
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}