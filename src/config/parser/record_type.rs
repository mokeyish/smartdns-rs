use super::*;

impl NomParser for RecordType {
    fn parse(input: &str) -> IResult<&str, Self> {
        map(u16, RecordType::from)(input)
    }
}
