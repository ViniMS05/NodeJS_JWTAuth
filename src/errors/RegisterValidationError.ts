import { ZodError } from "zod";

export function RegisterValidationError(error: ZodError) {
  const issues = error.issues;
  const initialIssuesValue: { path: (string | number)[]; message: string }[] =
    [];

  const formattedIssues = issues.reduce((acc, current) => {
    const issue = {
      path: current.path,
      message: current.message,
    };

    acc.push(issue);
    return acc;
  }, initialIssuesValue);

  return formattedIssues;
}
