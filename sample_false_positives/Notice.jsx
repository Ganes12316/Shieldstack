function Notice(props) {
  let brandHtml = props.brandHtml;
  brandHtml = sanitizeHtml(brandHtml);  // reassigned + sanitized — but same variable name
  return <div dangerouslySetInnerHTML={{ __html: brandHtml }} />;
}
