import { Link } from "react-router";

export function NotFoundPage() {
  return (
    <section>
      <h1>Not found</h1>
      <p>
        <Link to="/overview">Back to the overview</Link>
      </p>
    </section>
  );
}
