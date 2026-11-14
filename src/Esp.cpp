#include "Esp.h"

#include "Chain.h"  // arc::ParseUnsigned

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace arc {
namespace {

constexpr double kDegreesToRadians = 3.14159265358979323846 / 180.0;

[[nodiscard]] double ToRadians(double degrees) {
    return degrees * kDegreesToRadians;
}

[[nodiscard]] std::string Trim(std::string_view text) {
    std::size_t begin = 0;
    while (begin < text.size() && std::isspace(static_cast<unsigned char>(text[begin])) != 0) {
        ++begin;
    }
    std::size_t end = text.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1])) != 0) {
        --end;
    }
    return std::string(text.substr(begin, end));
}

// Keys are read as hex when they look like an address or an offset (0x...) and as decimal otherwise, which
// is what both the generated ini and a hand-edited one contain.
[[nodiscard]] std::optional<std::uint64_t> ParseInteger(const std::string& value) {
    if (value.empty()) {
        return std::nullopt;
    }
    const char* begin = value.c_str();
    char* end = nullptr;
    const auto parsed = std::strtoull(begin, &end, 0);
    if (end == begin) {
        return std::nullopt;
    }
    return parsed;
}

[[nodiscard]] std::optional<double> ParseReal(const std::string& value) {
    if (value.empty()) {
        return std::nullopt;
    }
    const char* begin = value.c_str();
    char* end = nullptr;
    const auto parsed = std::strtod(begin, &end);
    if (end == begin) {
        return std::nullopt;
    }
    return parsed;
}

[[nodiscard]] std::uint64_t OffsetOf(const std::optional<double>& value) {
    return value && *value >= 0.0 ? static_cast<std::uint64_t>(*value) : 0;
}

}  // namespace

bool IsPlausiblePosition(const FVector& value, double limit) {
    const double axes[3] = {value.x, value.y, value.z};
    for (const auto axis : axes) {
        if (!std::isfinite(axis)) {
            return false;
        }
        const double absolute = std::fabs(axis);
        // A pointer's half read as a float lands in the denormal band, and a stale vtable read lands far
        // outside any level - both are rejected here so no call site has to remember to.
        if (absolute > 0.0 && absolute < 1.0e-2) {
            return false;
        }
        if (absolute > limit) {
            return false;
        }
    }
    return true;
}

bool IsPositionCandidate(const FVector& value, double limit) {
    if (!IsPlausiblePosition(value, limit)) {
        return false;
    }
    // A zero axis makes the offset ambiguous by one float (the triple could have started one slot earlier),
    // so the scanner only accepts triples where every axis carries a real coordinate.
    return std::fabs(value.x) >= 1.0 && std::fabs(value.y) >= 1.0 && std::fabs(value.z) >= 1.0;
}

double DistanceMetres(const FVector& from, const FVector& to) {
    const double dx = to.x - from.x;
    const double dy = to.y - from.y;
    const double dz = to.z - from.z;
    return std::sqrt(dx * dx + dy * dy + dz * dz) / 100.0;  // Unreal units are centimetres
}

void CameraBasis(const FRotator& rotation, FVector* forward, FVector* right, FVector* up) {
    const double pitch = ToRadians(rotation.pitch);
    const double yaw = ToRadians(rotation.yaw);
    const double cp = std::cos(pitch);
    const double sp = std::sin(pitch);
    const double cy = std::cos(yaw);
    const double sy = std::sin(yaw);
    if (forward != nullptr) {
        *forward = FVector{cp * cy, cp * sy, sp};
    }
    if (right != nullptr) {
        *right = FVector{-sy, cy, 0.0};
    }
    if (up != nullptr) {
        *up = FVector{-sp * cy, -sp * sy, cp};
    }
}

double Viewport::VerticalFovDegrees() const {
    const double aspect = height == 0 ? 1.0 : static_cast<double>(width) / static_cast<double>(height);
    const double half = std::tan(ToRadians(fov_degrees) * 0.5) / (aspect <= 0.0 ? 1.0 : aspect);
    return 2.0 * std::atan(half) / kDegreesToRadians;
}

Viewport EspOffsetSet::ScreenView() const noexcept {
    Viewport view;
    view.eye = local_origin;
    view.rotation = FRotator{view_pitch_degrees, view_yaw_degrees, 0.0};
    view.fov_degrees = fov_degrees;
    view.width = screen_width;
    view.height = screen_height;
    return view;
}

bool WorldToScreen(const FVector& world, const Viewport& view, double* out_x, double* out_y,
    double* out_depth_cm) {
    FVector forward{};
    FVector right{};
    FVector up{};
    CameraBasis(view.rotation, &forward, &right, &up);
    const FVector delta{world.x - view.eye.x, world.y - view.eye.y, world.z - view.eye.z};
    const double depth = delta.x * forward.x + delta.y * forward.y + delta.z * forward.z;
    if (!(depth > view.near_cm) || !std::isfinite(depth)) {
        return false;  // behind the camera or inside the near plane
    }
    const double lateral = delta.x * right.x + delta.y * right.y + delta.z * right.z;
    const double vertical = delta.x * up.x + delta.y * up.y + delta.z * up.z;
    const double tan_half_h = std::tan(ToRadians(view.fov_degrees) * 0.5);
    const double tan_half_v = std::tan(ToRadians(view.VerticalFovDegrees()) * 0.5);
    if (std::fabs(tan_half_h) < 1.0e-9 || std::fabs(tan_half_v) < 1.0e-9) {
        return false;
    }
    const double ndc_x = lateral / depth / tan_half_h;
    const double ndc_y = vertical / depth / tan_half_v;
    if (out_x != nullptr) {
        *out_x = (ndc_x * 0.5 + 0.5) * static_cast<double>(view.width);
    }
    if (out_y != nullptr) {
        *out_y = (0.5 - ndc_y * 0.5) * static_cast<double>(view.height);
    }
    if (out_depth_cm != nullptr) {
        *out_depth_cm = depth;
    }
    return std::isfinite(ndc_x) && std::isfinite(ndc_y);
}

double ScreenRadiusPixels(double depth_cm, double radius_cm, const Viewport& view) {
    if (!(depth_cm > view.near_cm)) {
        return 0.0;
    }
    const double tan_half_v = std::tan(ToRadians(view.VerticalFovDegrees()) * 0.5);
    if (std::fabs(tan_half_v) < 1.0e-9) {
        return 0.0;
    }
    return (radius_cm / depth_cm) / tan_half_v * (static_cast<double>(view.height) * 0.5);
}

EspOffsetSet ParseEspConfig(const std::string& text) {
    EspOffsetSet offsets;
    bool in_esp = false;
    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        const auto comment = line.find('#');
        if (comment != std::string::npos) {
            line.erase(comment);
        }
        const auto trimmed = Trim(line);
        if (trimmed.empty()) {
            continue;
        }
        if (trimmed.front() == '[' && trimmed.back() == ']') {
            in_esp = Trim(trimmed.substr(1, trimmed.size() - 2)) == "esp";
            continue;
        }
        if (!in_esp) {
            continue;
        }
        const auto equals = trimmed.find('=');
        if (equals == std::string::npos) {
            continue;
        }
        const auto key = Trim(trimmed.substr(0, equals));
        const auto value = Trim(trimmed.substr(equals + 1));
        const auto number = ParseInteger(value);
        const auto real = ParseReal(value);
        const auto field = [&](std::uint64_t& target) {
            if (number) {
                target = *number;
            }
        };
        if (key == "global_rva") {
            field(offsets.global_rva);
        } else if (key == "chain") {
            offsets.chain.clear();
            std::string current;
            for (const char character : value) {
                if (character == ',' || character == ' ') {
                    if (!current.empty()) {
                        if (const auto step = ParseInteger(Trim(current))) {
                            offsets.chain.push_back(*step);
                        }
                        current.clear();
                    }
                } else {
                    current.push_back(character);
                }
            }
            if (!current.empty()) {
                if (const auto step = ParseInteger(Trim(current))) {
                    offsets.chain.push_back(*step);
                }
            }
        } else if (key == "persistent_level_off") {
            field(offsets.persistent_level_off);
        } else if (key == "level_actors_off") {
            field(offsets.level_actors_off);
        } else if (key == "level_owning_world_off") {
            field(offsets.level_owning_world_off);
        } else if (key == "world_va") {
            field(offsets.world_va);
        } else if (key == "actor_array_data") {
            field(offsets.actor_array_data);
        } else if (key == "actor_array_num") {
            field(offsets.actor_array_num);
        } else if (key == "root_component_off") {
            field(offsets.root_component_off);
        } else if (key == "relative_location_off") {
            field(offsets.relative_location_off);
        } else if (key == "camera_manager_off") {
            field(offsets.camera_manager_off);
        } else if (key == "camera_cache_off") {
            field(offsets.camera_cache_off);
        } else if (key == "camera_position_off") {
            field(offsets.camera_position_off);
        } else if (key == "camera_rotation_off") {
            field(offsets.camera_rotation_off);
        } else if (key == "camera_fov_off") {
            field(offsets.camera_fov_off);
        } else if (key == "pawn_off") {
            field(offsets.pawn_off);
        } else if (key == "player_state_off") {
            field(offsets.player_state_off);
        } else if (key == "health_off") {
            field(offsets.health_off);
        } else if (key == "max_health_off") {
            field(offsets.max_health_off);
        } else if (key == "team_off") {
            field(offsets.team_off);
        } else if (key == "name_off") {
            field(offsets.name_off);
        } else if (key == "local_x") {
            if (real) {
                offsets.local_origin.x = *real;
            }
        } else if (key == "local_y") {
            if (real) {
                offsets.local_origin.y = *real;
            }
        } else if (key == "local_z") {
            if (real) {
                offsets.local_origin.z = *real;
            }
        } else if (key == "view_pitch_degrees") {
            if (real) {
                offsets.view_pitch_degrees = *real;
            }
        } else if (key == "view_yaw_degrees") {
            if (real) {
                offsets.view_yaw_degrees = *real;
            }
        } else if (key == "local_controller_va") {
            field(offsets.local_controller_va);
        } else if (key == "fov_degrees") {
            if (real) {
                offsets.fov_degrees = *real;
            }
        } else if (key == "screen_width") {
            offsets.screen_width = static_cast<std::uint32_t>(OffsetOf(real));
        } else if (key == "screen_height") {
            offsets.screen_height = static_cast<std::uint32_t>(OffsetOf(real));
        } else if (key == "actor_radius_cm") {
            if (real) {
                offsets.actor_radius_cm = *real;
            }
        }
    }
    return offsets;
}

EspOffsetSet LoadEspConfig(const std::filesystem::path& path) {
    std::ifstream in(path.string());  // .string(), because the path is wide-native under _WIN32
    if (!in) {
        throw std::runtime_error("cannot open " + path.string());
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return ParseEspConfig(buffer.str());
}

namespace {

[[nodiscard]] std::optional<FVector> ReadTriple(const IMemory& memory, std::uint64_t va) {
    const auto x = memory.Float(va);
    const auto y = memory.Float(va + 4);
    const auto z = memory.Float(va + 8);
    if (!x || !y || !z) {
        return std::nullopt;
    }
    return FVector{*x, *y, *z};
}

}  // namespace

std::vector<EspActor> ReadActors(const IMemory& memory, const EspOffsetSet& offsets, std::size_t limit) {
    std::vector<EspActor> rows;
    if (!offsets.HasPositions() || !offsets.HasActorList()) {
        return rows;
    }
    const auto view = offsets.ScreenView();
    const auto count = std::min<std::size_t>(static_cast<std::size_t>(offsets.actor_array_num), limit);
    for (std::size_t i = 0; i < count; ++i) {
        const auto actor = memory.Qword(offsets.actor_array_data + i * 8);
        if (!actor || *actor < 0x1000) {
            continue;
        }
        const auto component = memory.Qword(*actor + offsets.root_component_off);
        if (!component || *component < 0x1000) {
            continue;
        }
        const auto position = ReadTriple(memory, *component + offsets.relative_location_off);
        if (!position || !IsPlausiblePosition(*position)) {
            continue;
        }
        EspActor row;
        row.address = *actor;
        row.position = *position;
        row.distance_m = DistanceMetres(offsets.local_origin, *position);
        double depth = 0.0;
        row.projected = WorldToScreen(*position, view, &row.screen_x, &row.screen_y, &depth);
        if (row.projected) {
            row.box_half_height = ScreenRadiusPixels(depth, offsets.actor_radius_cm, view);
        }
        if (offsets.health_off != 0) {
            const auto health = memory.Float(*actor + offsets.health_off);
            std::optional<float> maximum;
            if (offsets.max_health_off != 0) {
                maximum = memory.Float(*actor + offsets.max_health_off);
            }
            // A zero or a health greater than the maximum is the signature of reading an unrelated field,
            // and an overlay that shows "0/0" for everything is worse than one that shows nothing.
            if (health && *health > 0.0F && *health < 1.0e6F && (!maximum || *maximum <= 0.0F ||
                    *health <= *maximum)) {
                row.has_health = true;
                row.health = *health;
                row.max_health = maximum && *maximum > 0.0F ? *maximum : 0.0F;
            }
        }
        if (offsets.team_off != 0) {
            if (const auto team = memory.Dword(*actor + offsets.team_off)) {
                row.has_team = true;
                row.team = *team;
            }
        }
        rows.push_back(row);
    }
    return rows;
}

bool ReadLocalView(const IMemory& memory, std::uint64_t player_controller, const EspOffsetSet& offsets,
    Viewport* view) {
    if (view == nullptr || player_controller == 0 || offsets.camera_manager_off == 0 ||
        offsets.camera_position_off == 0) {
        return false;
    }
    const auto manager = memory.Qword(player_controller + offsets.camera_manager_off);
    if (!manager || *manager < 0x1000) {
        return false;
    }
    const auto cache = *manager + offsets.camera_cache_off;
    const auto position = ReadTriple(memory, cache + offsets.camera_position_off);
    if (!position || !IsPlausiblePosition(*position)) {
        return false;
    }
    view->eye = *position;
    if (offsets.camera_rotation_off != 0) {
        const auto pitch = memory.Float(cache + offsets.camera_rotation_off);
        const auto yaw = memory.Float(cache + offsets.camera_rotation_off + 4);
        if (pitch && yaw && std::isfinite(*pitch) && std::isfinite(*yaw)) {
            view->rotation = FRotator{*pitch, *yaw, 0.0};
        }
    }
    if (offsets.camera_fov_off != 0) {
        if (const auto fov = memory.Float(cache + offsets.camera_fov_off); fov && *fov > 1.0F && *fov < 179.0F) {
            view->fov_degrees = *fov;
        }
    }
    return true;
}

namespace {

[[nodiscard]] bool HasSuffix(const std::string_view text, std::string_view suffix) {
    return text.size() >= suffix.size() &&
        text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

[[nodiscard]] bool Number(const std::string_view text, std::uint64_t* out) {
    try {
        const auto value = ParseUnsigned(text);
        if (out != nullptr) {
            *out = value;
        }
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

}  // namespace

std::filesystem::path SiblingPath(const std::filesystem::path& file, const std::string_view name) {
    auto text = file.string();
    const auto cut = text.find_last_of("/\\");
    if (cut == std::string::npos) {
        return std::filesystem::path(std::string(name));  // the page sits in the working directory
    }
    return std::filesystem::path(text.substr(0, cut + 1) + std::string(name));
}

std::optional<OverlayRequest> ParseOverlayArgs(const std::vector<std::string_view>& args) {
    if (args.empty() || args.size() > 2) {
        return std::nullopt;
    }
    OverlayRequest request;
    request.html = std::string(args[0]);
    if (args.size() == 2) {
        if (args[1] != "demo") {
            return std::nullopt;  // a typo here must not silently skip the demo file
        }
        request.demo = true;
    }
    return request;
}

std::optional<ConfigRequest> ParseConfigArgs(const std::vector<std::string_view>& args) {
    if (args.size() != 1) {
        return std::nullopt;
    }
    return ConfigRequest{std::string(args[0])};
}

std::optional<ExportRequest> ParseExportArgs(const std::vector<std::string_view>& args) {
    if (args.size() < 4) {
        return std::nullopt;
    }
    ExportRequest request;
    request.dump = std::string(args[0]);
    if (!Number(args[1], &request.base) || !Number(args[2], &request.image_size) || request.base == 0 ||
        request.image_size == 0) {
        return std::nullopt;
    }
    // The tail is classified by shape, not position: PowerShell is free to drop an empty "" argument, and
    // ".ini/.txt/.cfg" is always the config while ".js/.json" is always the output.
    bool have_rows = false;
    for (std::size_t i = 3; i < args.size(); ++i) {
        const auto arg = args[i];
        if (HasSuffix(arg, ".js") || HasSuffix(arg, ".json")) {
            request.out = std::string(arg);
            continue;
        }
        if (HasSuffix(arg, ".ini") || HasSuffix(arg, ".txt") || HasSuffix(arg, ".cfg")) {
            if (request.config.empty()) {
                request.config = std::string(arg);
            } else {
                request.out = std::string(arg);
            }
            continue;
        }
        if (!have_rows && Number(arg, &request.rows)) {
            have_rows = true;
            continue;
        }
        return std::nullopt;
    }
    if (request.config.empty()) {
        return std::nullopt;
    }
    return request;
}

std::optional<AimPick> SelectAimTarget(const std::vector<EspActor>& rows, const double aim_x,
    const double aim_y, const double max_offset_px) {
    std::optional<AimPick> best;
    for (std::size_t i = 0; i < rows.size(); ++i) {
        const auto& row = rows[i];
        if (!row.projected) {
            continue;  // behind the camera: aiming at it would fling the view around
        }
        const double dx = row.screen_x - aim_x;
        const double dy = row.screen_y - aim_y;
        const double offset = std::sqrt(dx * dx + dy * dy);
        if (!(offset <= max_offset_px)) {
            continue;
        }
        if (!best || offset < best->offset_px) {
            best = AimPick{i, offset, row.distance_m};
        }
    }
    return best;
}

bool IsOnAimPoint(const EspActor& row, const double aim_x, const double aim_y, const double slack_px) {
    if (!row.projected || row.box_half_height <= 0.0) {
        return false;
    }
    const double half_width = row.box_half_height * 0.25;  // the exporter draws a 1:2 box
    const double top = row.screen_y - row.box_half_height * 0.5;
    const double bottom = row.screen_y + row.box_half_height * 0.5;
    const double left = row.screen_x - half_width;
    const double right = row.screen_x + half_width;
    return aim_x >= left - slack_px && aim_x <= right + slack_px && aim_y >= top - slack_px &&
        aim_y <= bottom + slack_px;
}

std::string ToJson(const std::vector<EspActor>& rows, const EspOffsetSet& offsets, std::size_t total_actors,
    bool as_js, std::string_view note) {
    const auto num = [](double value) {
        std::ostringstream out;
        out.precision(2);
        out << std::fixed << value;
        return out.str();
    };
    std::ostringstream out;
    out << "{\n";
    out << "  \"note\": \"" << Trim(note) << "\",\n";
    out << "  \"actors_total\": " << total_actors << ",\n";
    out << "  \"actors_with_position\": " << rows.size() << ",\n";
    out << "  \"screen\": {\"width\": " << offsets.screen_width << ", \"height\": " << offsets.screen_height
        << ", \"fov\": " << num(offsets.fov_degrees) << "},\n";
    out << "  \"camera\": {\"x\": " << num(offsets.local_origin.x) << ", \"y\": " << num(offsets.local_origin.y)
        << ", \"z\": " << num(offsets.local_origin.z) << ", \"pitch\": " << num(offsets.view_pitch_degrees)
        << ", \"yaw\": " << num(offsets.view_yaw_degrees) << ", \"present\": "
        << (offsets.camera_position_off != 0 ? "true" : "false") << "},\n";
    out << "  \"offsets\": {\"root_component\": " << offsets.root_component_off << ", \"relative_location\": "
        << offsets.relative_location_off << ", \"actor_array\": " << offsets.actor_array_data << ", "
        "\"level_actors\": " << offsets.level_actors_off << ", \"persistent_level\": "
        << offsets.persistent_level_off << "},\n";
    out << "  \"rows\": [";
    for (std::size_t i = 0; i < rows.size(); ++i) {
        const auto& row = rows[i];
        std::ostringstream id;
        id << "0x" << std::hex << row.address;
        out << (i == 0 ? "\n" : ",\n") << "    {\"id\": \"" << id.str() << "\", \"x\": "
            << num(row.position.x)
            << ", \"y\": " << num(row.position.y)
            << ", \"z\": " << num(row.position.z) << ", \"dist\": "
            << num(row.distance_m) << ", \"screen\": " << (row.projected ? "true" : "false") << ", \"sx\": "
            << num(row.screen_x) << ", \"sy\": " << num(row.screen_y) << ", \"h\": "
            << num(row.box_half_height * 2.0) << ", \"hp\": "
            << (row.has_health ? num(row.health) : std::string("null")) << ", \"hpmax\": "
            << (row.has_health && row.max_health > 0.0F ? num(row.max_health) : std::string("null")) << ", \"team\": "
            << (row.has_team ? std::to_string(row.team) : std::string("null")) << "}";
    }
    out << (rows.empty() ? "" : "\n  ") << "]\n}\n";
    if (!as_js) {
        return out.str();
    }
    return "window.ARC = " + out.str() + ";\n";
}

std::string DemoOverlayData() {
    EspOffsetSet offsets;
    offsets.screen_width = 1920;
    offsets.screen_height = 1080;
    offsets.fov_degrees = 90.0;
    offsets.actor_radius_cm = 85.0;
    offsets.relative_location_off = 0x11C;   // only echoed into the json, nothing is read here
    offsets.root_component_off = 0x130;

    const Viewport view = offsets.ScreenView();
    std::vector<EspActor> rows;
    for (std::size_t i = 0; i < 12; ++i) {
        const double angle = static_cast<double>(i) / 12.0 * 6.283185307179586;
        EspActor row;
        row.address = 0x1000 + i * 0x10;
        row.position = FVector{2500.0 + 900.0 * std::cos(angle), 1800.0 * std::sin(angle), 100.0 + 60.0 * i};
        row.distance_m = DistanceMetres(offsets.local_origin, row.position);
        double depth = 0.0;
        row.projected = WorldToScreen(row.position, view, &row.screen_x, &row.screen_y, &depth);
        row.box_half_height = row.projected ? ScreenRadiusPixels(depth, offsets.actor_radius_cm, view) : 0.0;
        row.has_health = true;
        row.health = static_cast<float>(38 + 9 * i);
        row.max_health = 100.0F;
        row.has_team = true;
        row.team = static_cast<std::uint32_t>(i % 3);
        rows.push_back(row);
    }
    return ToJson(rows, offsets, rows.size(), true,
        "demo data: the overlay, the projection and the reader work; these actors are not real");
}

std::string OverlayHtml() {
    // A single file with no dependencies: it loads `esp-data.js` (the file `esp-export` writes when the
    // output name ends in .js), redraws on a timer, and shows what it is waiting for. The reason it reads a
    // .js assignment instead of fetch()-ing a .json is that file:// blocks the latter in every browser, and
    // an overlay that needs a local web server is not an overlay anyone will run twice.
    return R"HTML(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ARC ESP overlay</title>
<style>
  html, body { margin: 0; height: 100%; background: #06070a; overflow: hidden;
               font: 12px/1.4 ui-monospace, Consolas, monospace; color: #cdd3de; }
  canvas { display: block; width: 100vw; height: 100vh; }
  #hud { position: fixed; left: 8px; top: 8px; white-space: pre; text-shadow: 0 1px 2px #000; }
  #hud b { color: #7fd1ff; }
</style>
</head>
<body>
<canvas id="c"></canvas>
<div id="hud">waiting for esp-data.js - run:
  arc_tool esp-export &lt;dump&gt; &lt;base&gt; &lt;size&gt; esp.ini esp-data.js
</div>
<script src="esp-data.js"></script>
<script>
const canvas = document.getElementById('c');
const hud = document.getElementById('hud');
const ctx = canvas.getContext('2d');

// Reload the data file on a timer; the query string only defeats the cache.
let stamp = 0;
function poll() {
  const s = document.createElement('script');
  s.src = 'esp-data.js?t=' + (++stamp);
  s.onload = () => s.remove();
  s.onerror = () => { hud.textContent = 'esp-data.js not found yet'; s.remove(); };
  document.head.appendChild(s);
}
setInterval(poll, 300);
poll();

function draw() {
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
    canvas.width = w * dpr; canvas.height = h * dpr;
  }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  const data = window.ARC;
  if (!data) { requestAnimationFrame(draw); return; }
  // The exporter wrote positions for the screen size in the ini, so scale the drawing instead of asking
  // the user to match their window to it.
  const sx = w / (data.screen.width || 1920);
  const sy = h / (data.screen.height || 1080);
  const rows = data.rows || [];
  ctx.lineWidth = 1;
  for (const row of rows) {
    if (!row.screen) { continue; }
    const x = row.sx * sx, y = row.sy * sy, box = row.h * sy;
    if (box <= 0 || !isFinite(x) || !isFinite(y)) { continue; }
    const top = y - box / 2, left = x - box / 4;
    const enemy = data.team !== undefined && row.team !== null && row.team !== data.team;
    ctx.strokeStyle = enemy ? '#ff5f56' : '#7fd1ff';
    ctx.strokeRect(left, top, box / 2, box);
    ctx.beginPath();
    ctx.moveTo(x, top - 4); ctx.lineTo(x, top);
    ctx.moveTo(x, top + box); ctx.lineTo(x, top + box + 4);
    ctx.stroke();
    ctx.fillStyle = '#e6ebf2';
    const label = row.dist.toFixed(1) + ' m' + (row.hp !== null ? '  ' + row.hp.toFixed(0) : '') +
                  (row.team !== null ? '  t' + row.team : '') + '  ' + row.id;
    ctx.fillText(label, left, top - 7);
    if (row.hp !== null && row.hpmax) {
      const pct = Math.max(0, Math.min(1, row.hp / row.hpmax));
      ctx.fillStyle = '#242a33';
      ctx.fillRect(left, top + box + 3, box / 2, 3);
      ctx.fillStyle = '#57d38b';
      ctx.fillRect(left, top + box + 3, box / 2 * pct, 3);
    }
  }
  ctx.strokeStyle = 'rgba(200,215,235,.35)';
  ctx.beginPath();
  ctx.moveTo(w / 2 - 8, h / 2); ctx.lineTo(w / 2 + 8, h / 2);
  ctx.moveTo(w / 2, h / 2 - 8); ctx.lineTo(w / 2, h / 2 + 8);
  ctx.stroke();
  hud.innerHTML = '<b>' + rows.length + '</b> of ' + data.actors_total + ' actors carry a position<br>' +
    'fov ' + (data.screen.fov || 0).toFixed(0) + '  screen ' + data.screen.width + 'x' + data.screen.height +
    '  camera ' + (data.camera.present ? 'from snapshot' : 'configured') + '<br>' +
    (data.note || '');
  requestAnimationFrame(draw);
}
requestAnimationFrame(draw);
</script>
</body>
</html>
)HTML";
}

}  // namespace arc
